//go:generate go tool oapi-codegen --config=types.cfg.yaml ../docs/api/openapi.yaml
//go:generate go tool oapi-codegen --config=server.cfg.yaml ../docs/api/openapi.yaml
//go:generate go tool oapi-codegen --config=client.cfg.yaml ../docs/api/openapi.yaml

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/go-chi/chi/v5"
	"github.com/miekg/dns"
)

type httpReqCtxKey struct{}

// BlockingStatus represents the current blocking status
type BlockingStatus struct {
	// True if blocking is enabled
	Enabled bool `json:"enabled"`
	// Disabled group names
	DisabledGroups []string `json:"disabledGroups"`
	// If blocking is temporary disabled: amount of seconds until blocking will be enabled
	AutoEnableInSec int `json:"autoEnableInSec"`
}

// BlockingControl interface to control the blocking status
type BlockingControl interface {
	EnableBlocking(ctx context.Context)
	DisableBlocking(ctx context.Context, duration time.Duration, disableGroups []string) error
	BlockingStatus() BlockingStatus
}

// BlockingControl interface to control the blocking status
type ClientDNSResolverControl interface {
	EnableClientDNSResolver(ctx context.Context)
	DisableClientDNSResolver(ctx context.Context, duration time.Duration, disableGroups []string) error
	ClientDNSResolverStatus() BlockingStatus
}

// ListRefresher interface to control the list refresh
type ListRefresher interface {
	RefreshLists() error
}

type Querier interface {
	Query(
		ctx context.Context, serverHost string, clientIP net.IP, question string, qType dns.Type,
	) (*model.Response, error)
}

type CacheControl interface {
	FlushCaches(ctx context.Context)
}

func RegisterOpenAPIEndpoints(router chi.Router, impl StrictServerInterface) {
	middleware := []StrictMiddlewareFunc{ctxWithHTTPRequestMiddleware}

	HandlerFromMuxWithBaseURL(NewStrictHandler(impl, middleware), router, "/api")
}

func ctxWithHTTPRequestMiddleware(handler StrictHandlerFunc, operationID string) StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (response any, err error) {
		ctx = context.WithValue(ctx, httpReqCtxKey{}, r)

		return handler(ctx, w, r, request)
	}
}

type OpenAPIInterfaceImpl struct {
	control      BlockingControl
	dnsControl   ClientDNSResolverControl
	querier      Querier
	refresher    ListRefresher
	cacheControl CacheControl
}

func NewOpenAPIInterfaceImpl(control BlockingControl,
	querier Querier,
	refresher ListRefresher,
	cacheControl CacheControl,
) *OpenAPIInterfaceImpl {
	return &OpenAPIInterfaceImpl{
		control:      control,
		querier:      querier,
		refresher:    refresher,
		cacheControl: cacheControl,
	}
}

func (i *OpenAPIInterfaceImpl) DisableBlocking(ctx context.Context,
	request DisableBlockingRequestObject,
) (DisableBlockingResponseObject, error) {
	var (
		duration time.Duration
		groups   []string
		err      error
	)

	if request.Params.Duration != nil {
		duration, err = time.ParseDuration(*request.Params.Duration)
		if err != nil {
			return DisableBlocking400TextResponse(log.EscapeInput(err.Error())), nil
		}
	}

	if request.Params.Groups != nil && len(*request.Params.Groups) > 0 {
		groups = strings.Split(*request.Params.Groups, ",")
	}

	err = i.control.DisableBlocking(ctx, duration, groups)
	if err != nil {
		return DisableBlocking400TextResponse(log.EscapeInput(err.Error())), nil
	}

	return DisableBlocking200Response{}, nil
}

func (i *OpenAPIInterfaceImpl) EnableBlocking(ctx context.Context, _ EnableBlockingRequestObject,
) (EnableBlockingResponseObject, error) {
	i.control.EnableBlocking(ctx)

	return EnableBlocking200Response{}, nil
}

func (i *OpenAPIInterfaceImpl) BlockingStatus(_ context.Context, _ BlockingStatusRequestObject,
) (BlockingStatusResponseObject, error) {
	blStatus := i.control.BlockingStatus()

	result := ApiBlockingStatus{
		Enabled: blStatus.Enabled,
	}

	if blStatus.AutoEnableInSec > 0 {
		result.AutoEnableInSec = &blStatus.AutoEnableInSec
	}

	if len(blStatus.DisabledGroups) > 0 {
		result.DisabledGroups = &blStatus.DisabledGroups
	}

	return BlockingStatus200JSONResponse(result), nil
}

func (i *OpenAPIInterfaceImpl) ListRefresh(_ context.Context,
	_ ListRefreshRequestObject,
) (ListRefreshResponseObject, error) {
	err := i.refresher.RefreshLists()
	if err != nil {
		return ListRefresh500TextResponse(log.EscapeInput(err.Error())), nil
	}

	return ListRefresh200Response{}, nil
}

func (i *OpenAPIInterfaceImpl) Query(ctx context.Context, request QueryRequestObject) (QueryResponseObject, error) {
	qType := dns.Type(dns.StringToType[request.Body.Type])
	if qType == dns.Type(dns.TypeNone) {
		return Query400TextResponse(fmt.Sprintf("unknown query type '%s'", request.Body.Type)), nil
	}

	var (
		serverHost string
		clientIP   net.IP
	)

	httpReq, ok := ctx.Value(httpReqCtxKey{}).(*http.Request)
	if ok {
		serverHost = httpReq.Host
		clientIP = util.HTTPClientIP(httpReq)
	}

	resp, err := i.querier.Query(ctx, serverHost, clientIP, dns.Fqdn(request.Body.Query), qType)
	if err != nil {
		return nil, err
	}

	return Query200JSONResponse(ApiQueryResult{
		Reason:       resp.Reason,
		ResponseType: resp.RType.String(),
		Response:     util.AnswerToString(resp.Res.Answer),
		ReturnCode:   dns.RcodeToString[resp.Res.Rcode],
	}), nil
}

func (i *OpenAPIInterfaceImpl) CacheFlush(ctx context.Context,
	_ CacheFlushRequestObject,
) (CacheFlushResponseObject, error) {
	i.cacheControl.FlushCaches(ctx)

	return CacheFlush200Response{}, nil
}

// apiClientDNSResolverEnable is the http endpoint to enable the client dns resolver status
// @Summary Enable client dns resolver
// @Description enable the client dns resolver status
// @Tags blocking
// @Success 200   "Blocking is enabled"
// @Router /blocking/enable [get]
func (i *OpenAPIInterfaceImpl) clientDNSResolverEnable(ctx context.Context,
	rw http.ResponseWriter, _ *http.Request,
) {
	log.Log().Info("enabling blocking...")

	i.dnsControl.EnableClientDNSResolver(ctx)

	_, err := rw.Write([]byte("{}"))
	if err != nil {
		log.Log().Error("Can't send an empty answer: ", log.EscapeInput(err.Error()))
	}
}

// apiDisableClientDNSResolver is the http endpoint to disable the blocking status
// @Summary Disable client dns resolver
// @Description disable the client dns resolver for client
// @Tags blocking
// @Param duration query string false "duration of blocking (Example: 300s, 5m, 1h, 5m30s)" Format(duration)
// @Param groups query string false "groups to disable (comma separated). If empty, disable all groups" Format(string)
// @Success 200   "Blocking is disabled"
// @Failure 400   "Wrong duration format"
// @Failure 400   "Unknown group"
// @Router /blocking/disable [get]
func (i *OpenAPIInterfaceImpl) apiClientDNSResolverDisable(ctx context.Context,
	rw http.ResponseWriter, req *http.Request,
) {
	var (
		duration time.Duration
		groups   []string
		err      error
	)

	// parse duration from query parameter
	durationParam := req.URL.Query().Get("duration")
	if len(durationParam) > 0 {
		duration, err = time.ParseDuration(durationParam)
		if err != nil {
			log.Log().Errorf("wrong duration format '%s'", log.EscapeInput(durationParam))
			rw.WriteHeader(http.StatusBadRequest)

			return
		}
	}

	groupsParam := req.URL.Query().Get("groups")
	if len(groupsParam) > 0 {
		groups = strings.Split(groupsParam, ",")
	}

	err = i.dnsControl.DisableClientDNSResolver(ctx, duration, groups)
	if err != nil {
		log.Log().Error("can't dns disable the blocking: ", log.EscapeInput(err.Error()))
		rw.WriteHeader(http.StatusBadRequest)
	} else {
		log.Log().Warn("Blocking request acknowledged but not sent to redis: ")
		rw.WriteHeader(http.StatusOK)
		_, err := rw.Write([]byte("{}"))
		if err != nil {
			log.Log().Error("Can't send an empty answer: ", log.EscapeInput(err.Error()))
		}
	}
}

// apiClientDNSResolverStatus is the http endpoint to get current client dns resolver status
// @Summary client dns resolver status
// @Description get current client dns resolver status
// @Tags client dns resolver
// @Produce  json
// @Success 200 {object} api.BlockingStatus "Returns current blocking status"
// @Router /blocking/status [get]
func (i *OpenAPIInterfaceImpl) apiClientDNSResolverStatus(ctx context.Context, rw http.ResponseWriter, _ *http.Request) {
	status := i.dnsControl.ClientDNSResolverStatus()

	response, err := json.Marshal(status)
	util.LogOnError(ctx, "unable to marshal response ", err)

	_, err = rw.Write(response)
	util.LogOnError(ctx, "unable to write response ", err)
}
