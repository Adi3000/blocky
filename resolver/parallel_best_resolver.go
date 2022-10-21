package resolver

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/miekg/dns"

	"github.com/mroth/weightedrand"
	"github.com/sirupsen/logrus"
)

const (
	upstreamDefaultCfgName = "default"
	parallelResolverLogger = "parallel_best_resolver"
	resolverCount          = 2
)

// ParallelBestResolver delegates the DNS message to 2 upstream resolvers and returns the fastest answer
type ParallelBestResolver struct {
	resolversPerClient map[string][]*upstreamResolverStatus
	status             *status
}

type upstreamResolverStatus struct {
	resolver      Resolver
	lastErrorTime atomic.Value
}

type requestResponse struct {
	response *model.Response
	err      error
}

// testResolver sends a test query to verify the resolver is reachable and working
func testResolver(r *UpstreamResolver) error {
	request := newRequest("github.com.", dns.Type(dns.TypeA))

	resp, err := r.Resolve(request)
	if err != nil || resp.RType != model.ResponseTypeRESOLVED {
		return fmt.Errorf("test resolve of upstream server failed: %w", err)
	}

	return nil
}

// NewParallelBestResolver creates new resolver instance
func NewParallelBestResolver(upstreamResolvers map[string][]config.Upstream, bootstrap *Bootstrap) (Resolver, error) {
	logger := logger("parallel resolver")
	s := make(map[string][]*upstreamResolverStatus)

	for name, res := range upstreamResolvers {
		var resolvers []*upstreamResolverStatus

		var errResolvers int

		for _, u := range res {
			r, err := NewUpstreamResolver(u, bootstrap)
			if err != nil {
				logger.Warnf("upstream group %s: %v", name, err)
				errResolvers++

				continue
			}

			if bootstrap != skipUpstreamCheck {
				err = testResolver(r)
				if err != nil {
					logger.Warn(err)
					errResolvers++
				}
			}

			resolver := &upstreamResolverStatus{
				resolver: r,
			}
			resolver.lastErrorTime.Store(time.Unix(0, 0))
			resolvers = append(resolvers, resolver)
		}

		if bootstrap != skipUpstreamCheck {
			if bootstrap.startVerifyUpstream && errResolvers == len(res) {
				return nil, fmt.Errorf("unable to reach any DNS resolvers configured for resolver group %s", name)
			}
		}

		s[name] = resolvers
	}

	if len(s[upstreamDefaultCfgName]) == 0 {
		return nil, fmt.Errorf("no external DNS resolvers configured as default upstream resolvers. "+
			"Please configure at least one under '%s' configuration name", upstreamDefaultCfgName)
	}

	res := &ParallelBestResolver{
		resolversPerClient: s,
		status: &status{
			enabled:     true,
			enableTimer: time.NewTimer(0),
		},
	}

	return res, nil
}

// Configuration returns current resolver configuration
func (r *ParallelBestResolver) Configuration() (result []string) {
	result = append(result, "upstream resolvers:")
	for name, res := range r.resolversPerClient {
		result = append(result, fmt.Sprintf("- %s", name))
		for _, r := range res {
			result = append(result, fmt.Sprintf("  - %s", r.resolver))
		}
	}

	return
}

func (r ParallelBestResolver) String() string {
	result := make([]string, 0)

	for name, res := range r.resolversPerClient {
		tmp := make([]string, len(res))
		for i, s := range res {
			tmp[i] = fmt.Sprintf("%s", s.resolver)
		}

		result = append(result, fmt.Sprintf("%s (%s)", name, strings.Join(tmp, ",")))
	}

	return fmt.Sprintf("parallel upstreams '%s'", strings.Join(result, "; "))
}

func (r *ParallelBestResolver) EnableClientDNSResolver() {
	r.status.lock.Lock()
	defer r.status.lock.Unlock()
	r.status.enableTimer.Stop()

	r.status.enabled = true
	r.status.disabledGroups = []string{}
}

// BlockingStatus returns the current blocking status
func (r *ParallelBestResolver) ClientDNSResolverStatus() api.BlockingStatus {
	var autoEnableDuration time.Duration

	r.status.lock.RLock()
	defer r.status.lock.RUnlock()

	if !r.status.enabled && r.status.disableEnd.After(time.Now()) {
		autoEnableDuration = time.Until(r.status.disableEnd)
	}

	return api.BlockingStatus{
		Enabled:         r.status.enabled,
		DisabledGroups:  r.status.disabledGroups,
		AutoEnableInSec: uint(autoEnableDuration.Seconds()),
	}
}

func (r *ParallelBestResolver) DisableClientDNSResolver(duration time.Duration, disableGroups []string) error {
	dnsStatus := r.status
	dnsStatus.lock.Lock()
	defer dnsStatus.lock.Unlock()
	dnsStatus.enableTimer.Stop()

	var allBlockingGroups []string

	for k := range r.resolversPerClient {
		if k != upstreamDefaultCfgName {
			allBlockingGroups = append(allBlockingGroups, k)
		}
	}

	sort.Strings(allBlockingGroups)

	if len(disableGroups) == 0 {
		dnsStatus.disabledGroups = allBlockingGroups
	} else {
		for _, g := range disableGroups {
			i := sort.SearchStrings(allBlockingGroups, g)
			if !(i < len(allBlockingGroups) && allBlockingGroups[i] == g) {
				return fmt.Errorf("group '%s' is unknown", g)
			}
		}
		dnsStatus.disabledGroups = disableGroups
	}

	dnsStatus.enabled = false

	dnsStatus.disableEnd = time.Now().Add(duration)

	if duration == 0 {
		log.Log().Infof("disable blocking with specific dns for group(s) '%s'", log.EscapeInput(strings.Join(dnsStatus.disabledGroups, "; ")))
	} else {
		log.Log().Infof("disable blocking with specific dns for %s for group(s) '%s'", duration,
			log.EscapeInput(strings.Join(dnsStatus.disabledGroups, "; ")))
		dnsStatus.enableTimer = time.AfterFunc(duration, func() {
			r.EnableClientDNSResolver()
			log.Log().Info("blocking with specific dns enabled again")
		})
	}

	return nil
}

func (r *ParallelBestResolver) filterClientsForResolver(clientNames []string) (filteredClientNames []string) {
	for _, cName := range clientNames {
		var toInclude = true

		for _, filteredCname := range r.status.disabledGroups {
			if util.ClientNameMatchesGroupName(filteredCname, cName) {
				toInclude = false
			}
		}

		if toInclude {
			filteredClientNames = append(filteredClientNames, cName)
		}
	}

	return filteredClientNames
}

func (r *ParallelBestResolver) resolversForClient(request *model.Request) (result []*upstreamResolverStatus) {

	overridedClientNames := r.filterClientsForResolver(request.ClientNames)
	// try client names
	for _, cName := range overridedClientNames {
		for clientDefinition, upstreams := range r.resolversPerClient {
			if util.ClientNameMatchesGroupName(clientDefinition, cName) {
				result = append(result, upstreams...)
			}
		}
	}

	// try IP
	upstreams, found := r.resolversPerClient[request.ClientIP.String()]

	if found {
		result = append(result, upstreams...)
	}

	// try CIDR
	for cidr, upstreams := range r.resolversPerClient {
		if util.CidrContainsIP(cidr, request.ClientIP) {
			result = append(result, upstreams...)
		}
	}

	if len(result) == 0 {
		// return default
		result = r.resolversPerClient[upstreamDefaultCfgName]
	}

	return result
}

// Resolve sends the query request to multiple upstream resolvers and returns the fastest result
func (r *ParallelBestResolver) Resolve(request *model.Request) (*model.Response, error) {
	logger := request.Log.WithField("prefix", parallelResolverLogger)

	resolvers := r.resolversForClient(request)

	if len(resolvers) == 1 {
		logger.WithField("resolver", resolvers[0].resolver).Debug("delegating to resolver")

		return resolvers[0].resolver.Resolve(request)
	}

	r1, r2 := pickRandom(resolvers)
	logger.Debugf("using %s and %s as resolver", r1.resolver, r2.resolver)

	ch := make(chan requestResponse, resolverCount)

	var collectedErrors []error

	logger.WithField("resolver", r1.resolver).Debug("delegating to resolver")

	go resolve(request, r1, ch)

	logger.WithField("resolver", r2.resolver).Debug("delegating to resolver")

	go resolve(request, r2, ch)

	//nolint: gosimple
	for len(collectedErrors) < resolverCount {
		select {
		case result := <-ch:
			if result.err != nil {
				logger.Debug("resolution failed from resolver, cause: ", result.err)
				collectedErrors = append(collectedErrors, result.err)
			} else {
				logger.WithFields(logrus.Fields{
					"resolver": r1.resolver,
					"answer":   util.AnswerToString(result.response.Res.Answer),
				}).Debug("using response from resolver")

				return result.response, nil
			}
		}
	}

	return nil, fmt.Errorf("resolution was not successful, used resolvers: '%s' and '%s' errors: %v",
		r1.resolver, r2.resolver, collectedErrors)
}

// pick 2 different random resolvers from the resolver pool
func pickRandom(resolvers []*upstreamResolverStatus) (resolver1, resolver2 *upstreamResolverStatus) {
	resolver1 = weightedRandom(resolvers, nil)
	resolver2 = weightedRandom(resolvers, resolver1.resolver)

	return
}

func weightedRandom(in []*upstreamResolverStatus, exclude Resolver) *upstreamResolverStatus {
	const errorWindowInSec = 60

	var choices []weightedrand.Choice

	for _, res := range in {
		var weight float64 = errorWindowInSec

		if time.Since(res.lastErrorTime.Load().(time.Time)) < time.Hour {
			// reduce weight: consider last error time
			lastErrorTime := res.lastErrorTime.Load().(time.Time)
			weight = math.Max(1, weight-(errorWindowInSec-time.Since(lastErrorTime).Minutes()))
		}

		if exclude != res.resolver {
			choices = append(choices, weightedrand.Choice{
				Item:   res,
				Weight: uint(weight),
			})
		}
	}

	c, _ := weightedrand.NewChooser(choices...)

	return c.Pick().(*upstreamResolverStatus)
}

func resolve(req *model.Request, resolver *upstreamResolverStatus, ch chan<- requestResponse) {
	resp, err := resolver.resolver.Resolve(req)

	// update the last error time
	if err != nil {
		resolver.lastErrorTime.Store(time.Now())
	}
	ch <- requestResponse{
		response: resp,
		err:      err,
	}
}
