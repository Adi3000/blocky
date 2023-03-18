package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"

	"github.com/0xERR0R/blocky/metrics"
	"github.com/0xERR0R/blocky/resolver"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/docs"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/0xERR0R/blocky/web"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/miekg/dns"
)

const (
	dohMessageLimit    = 512
	contentTypeHeader  = "content-type"
	cacheControlHeader = "cache-control"
	dnsContentType     = "application/dns-message"
	htmlContentType    = "text/html; charset=UTF-8"
	yamlContentType    = "text/yaml"
)

type ApiResponseWriter struct {
	ip string
}

func (r *ApiResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(r.ip)}
}
func (r *ApiResponseWriter) LocalAddr() net.Addr       { return nil }
func (r *ApiResponseWriter) WriteMsg(m *dns.Msg) error { return nil }
func (r *ApiResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (r *ApiResponseWriter) Close() error              { return nil }
func (r *ApiResponseWriter) TsigStatus() error         { return nil }
func (r *ApiResponseWriter) TsigTimersOnly(bool)       {}
func (r *ApiResponseWriter) Hijack()                   {}

func secureHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("strict-transport-security", "max-age=63072000")
		w.Header().Set("x-frame-options", "DENY")
		w.Header().Set("x-content-type-options", "nosniff")
		w.Header().Set("x-xss-protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) createOpenAPIInterfaceImpl() (impl api.StrictServerInterface, err error) {
	bControl, err := resolver.GetFromChainWithType[api.BlockingControl](s.queryResolver)
	if err != nil {
		return nil, fmt.Errorf("no blocking API implementation found %w", err)
	}

	refresher, err := resolver.GetFromChainWithType[api.ListRefresher](s.queryResolver)
	if err != nil {
		return nil, fmt.Errorf("no refresh API implementation found %w", err)
	}

	cacheControl, err := resolver.GetFromChainWithType[api.CacheControl](s.queryResolver)
	if err != nil {
		return nil, fmt.Errorf("no cache API implementation found %w", err)
	}

	return api.NewOpenAPIInterfaceImpl(bControl, s, refresher, cacheControl), nil
}

func (s *Server) registerDoHEndpoints(router *chi.Mux) {
	const pathDohQuery = "/dns-query"

	router.Get(pathDohQuery, s.dohGetRequestHandler)
	router.Get(pathDohQuery+"/", s.dohGetRequestHandler)
	router.Get(pathDohQuery+"/{clientID}", s.dohGetRequestHandler)
	router.Post(pathDohQuery, s.dohPostRequestHandler)
	router.Post(pathDohQuery+"/", s.dohPostRequestHandler)
	router.Post(pathDohQuery+"/{clientID}", s.dohPostRequestHandler)
}

func (s *Server) dohGetRequestHandler(rw http.ResponseWriter, req *http.Request) {
	dnsParam, ok := req.URL.Query()["dns"]
	if !ok || len(dnsParam[0]) < 1 {
		http.Error(rw, "dns param is missing", http.StatusBadRequest)

		return
	}

	rawMsg, err := base64.RawURLEncoding.DecodeString(dnsParam[0])
	if err != nil {
		http.Error(rw, "wrong message format", http.StatusBadRequest)

		return
	}

	if len(rawMsg) > dohMessageLimit {
		http.Error(rw, "URI Too Long", http.StatusRequestURITooLong)

		return
	}

	s.processDohMessage(rawMsg, rw, req)
}

func (s *Server) dohPostRequestHandler(rw http.ResponseWriter, req *http.Request) {
	contentType := req.Header.Get(contentTypeHeader)
	if contentType != dnsContentType {
		http.Error(rw, "unsupported content type", http.StatusUnsupportedMediaType)

		return
	}

	rawMsg, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	if len(rawMsg) > dohMessageLimit {
		http.Error(rw, "Payload Too Large", http.StatusRequestEntityTooLarge)

		return
	}

	s.processDohMessage(rawMsg, rw, req)
}

func (s *Server) processDohMessage(rawMsg []byte, rw http.ResponseWriter, httpReq *http.Request) {
	msg := new(dns.Msg)
	if err := msg.Unpack(rawMsg); err != nil {
		logger().Error("can't deserialize message: ", err)
		http.Error(rw, err.Error(), http.StatusBadRequest)

		return
	}

	ctx, dnsReq := newRequestFromHTTP(httpReq.Context(), httpReq, msg)

	s.handleReq(ctx, dnsReq, httpMsgWriter{rw})
}

type httpMsgWriter struct {
	rw http.ResponseWriter
}

func (r httpMsgWriter) WriteMsg(msg *dns.Msg) error {
	b, err := msg.Pack()
	if err != nil {
		return err
	}

	r.rw.Header().Set(contentTypeHeader, dnsContentType)

	// https://www.rfc-editor.org/rfc/rfc8484#section-5.1
	// get the smallest TTL from answer
	r.rw.Header().Set(cacheControlHeader, fmt.Sprintf("max-age=%d", getSmallestTTLFromAnswer(msg)))

	// https://www.rfc-editor.org/rfc/rfc8484#section-4.2.1
	r.rw.WriteHeader(http.StatusOK)

	_, err = r.rw.Write(b)

	return err
}

func getSmallestTTLFromAnswer(msg *dns.Msg) uint32 {
	var ttl uint32 = 0
	for _, a := range msg.Answer {
		if a.Header().Ttl < ttl || ttl == 0 {
			ttl = a.Header().Ttl
		}
	}

	return ttl
}

func (s *Server) Query(
	ctx context.Context, serverHost string, clientIP net.IP, question string, qType dns.Type,
) (*model.Response, error) {
	msg := util.NewMsgWithQuestion(question, qType)
	clientID := extractClientIDFromHost(serverHost)

	ctx, req := newRequest(ctx, clientIP, clientID, model.RequestProtocolTCP, msg)

	return s.resolve(ctx, req)
}

// apiQuery is the http endpoint to perform a DNS query
// @Summary Performs DNS query
// @Description Performs DNS query
// @Tags query
// @Accept  json
// @Produce  json
// @Param query body api.QueryRequest true "query data"
// @Success 200 {object} api.QueryResult "query was executed"
// @Failure 400   "Wrong request format"
// @Router /query [post]
func (s *Server) apiQuery(rw http.ResponseWriter, req *http.Request) {
	var queryRequest api.QueryRequest
	var apirw ApiResponseWriter

	rw.Header().Set(contentTypeHeader, jsonContentType)

	err := json.NewDecoder(req.Body).Decode(&queryRequest)
	if err != nil {
		logAndResponseWithError(err, "can't read request: ", rw)

		return
	}

	// validate query type
	qType := dns.Type(dns.StringToType[queryRequest.Type])
	if qType == dns.Type(dns.TypeNone) {
		err = fmt.Errorf("unknown query type '%s'", queryRequest.Type)
		logAndResponseWithError(err, "unknown query type: ", rw)

		return
	}

	query := queryRequest.Query

	// append dot
	if !strings.HasSuffix(query, ".") {
		query += "."
	}

	useRemoteAdress := queryRequest.UseRemoteAddress
	if useRemoteAdress {
		remoteAddr, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			logAndResponseWithError(err, "Cannot find remote url on "+req.RemoteAddr+" : ", rw)
			return
		} else {
			apirw = ApiResponseWriter{ip: remoteAddr}
		}
	} else if queryRequest.RemoteAddress != "" {
		apirw = ApiResponseWriter{ip: queryRequest.RemoteAddress}
	}

	dnsRequest := util.NewMsgWithQuestion(query, qType)
	r := createResolverRequest(&apirw, dnsRequest)

	response, err := s.queryResolver.Resolve(r)
	if err != nil {
		logAndResponseWithError(err, "unable to process query: ", rw)

		return
	}

	jsonResponse, err := json.Marshal(api.QueryResult{
		Reason:       response.Reason,
		ResponseType: response.RType.String(),
		Response:     util.AnswerToString(response.Res.Answer),
		ReturnCode:   dns.RcodeToString[response.Res.Rcode],
	})
	if err != nil {
		logAndResponseWithError(err, "unable to marshal response: ", rw)

		return
	}

	_, err = rw.Write(jsonResponse)
	logAndResponseWithError(err, "unable to write response: ", rw)
}

func createHTTPRouter(cfg *config.Config, openAPIImpl api.StrictServerInterface) *chi.Mux {
	router := chi.NewRouter()

	api.RegisterOpenAPIEndpoints(router, openAPIImpl)

	configureDebugHandler(router)

	configureDocsHandler(router)

	configureStaticAssetsHandler(router)

	configureRootHandler(cfg, router)

	metrics.Start(router, cfg.Prometheus)

	return router
}

func configureDocsHandler(router *chi.Mux) {
	router.Get("/docs/openapi.yaml", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(contentTypeHeader, yamlContentType)
		_, err := writer.Write([]byte(docs.OpenAPI))
		logAndResponseWithError(err, "can't write OpenAPI definition file: ", writer)
	})
}

func configureStaticAssetsHandler(router *chi.Mux) {
	assets, err := web.Assets()
	util.FatalOnError("unable to load static asset files", err)

	fs := http.FileServer(http.FS(assets))
	router.Handle("/static/*", http.StripPrefix("/static/", fs))
}

func configureRootHandler(cfg *config.Config, router *chi.Mux) {
	router.Get("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(contentTypeHeader, htmlContentType)

		t := template.New("index")

		_, _ = t.Parse(web.IndexTmpl)

		type HandlerLink struct {
			URL   string
			Title string
		}

		type PageData struct {
			Links     []HandlerLink
			Version   string
			BuildTime string
		}

		pd := PageData{
			Links:     nil,
			Version:   util.Version,
			BuildTime: util.BuildTime,
		}

		pd.Links = []HandlerLink{
			{
				URL:   "/docs/openapi.yaml",
				Title: "Rest API Documentation (OpenAPI)",
			},
			{
				URL:   "/static/rapidoc.html",
				Title: "Interactive Rest API Documentation (RapiDoc)",
			},
			{
				URL:   "/debug/",
				Title: "Go Profiler",
			},
		}

		if cfg.Prometheus.Enable {
			pd.Links = append(pd.Links, HandlerLink{
				URL:   cfg.Prometheus.Path,
				Title: "Prometheus endpoint",
			})
		}

		err := t.Execute(writer, pd)
		logAndResponseWithError(err, "can't write index template: ", writer)
	})
}

func logAndResponseWithError(err error, message string, writer http.ResponseWriter) {
	if err != nil {
		log.Log().Error(message, log.EscapeInput(err.Error()))
		http.Error(writer, err.Error(), http.StatusInternalServerError)
	}
}

func configureDebugHandler(router *chi.Mux) {
	router.Mount("/debug", middleware.Profiler())
}
