package resolver

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/0xERR0R/blocky/api"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/log"
	"github.com/0xERR0R/blocky/model"
	"github.com/0xERR0R/blocky/util"
	"github.com/sirupsen/logrus"
)

const (
	upstreamTreeResolverType = "upstream_tree"
)

type UpstreamTreeResolver struct {
	configurable[*config.Upstreams]
	typed

	branches map[string]Resolver
	status   *status
}

func NewUpstreamTreeResolver(ctx context.Context, cfg config.Upstreams, bootstrap *Bootstrap) (Resolver, error) {
	if len(cfg.Groups[upstreamDefaultCfgName]) == 0 {
		return nil, fmt.Errorf("no external DNS resolvers configured as default upstream resolvers. "+
			"Please configure at least one under '%s' configuration name", upstreamDefaultCfgName)
	}

	branches, err := createUpstreamBranches(ctx, cfg, bootstrap)
	if err != nil {
		return nil, err
	}

	if len(branches) == 1 {
		for _, r := range branches {
			return r, nil
		}
	}

	// return resolver that forwards request to specific resolver branch depending on the client
	r := UpstreamTreeResolver{
		configurable: withConfig(&cfg),
		typed:        withType(upstreamTreeResolverType),

		branches: branches,
		status: &status{
			enabled:     true,
			enableTimer: time.NewTimer(0),
		},
	}

	return &r, nil
}

func createUpstreamBranches(
	ctx context.Context, cfg config.Upstreams, bootstrap *Bootstrap,
) (map[string]Resolver, error) {
	branches := make(map[string]Resolver, len(cfg.Groups))
	errs := make([]error, 0, len(cfg.Groups))

	for group, upstreams := range cfg.Groups {
		var (
			upstream Resolver
			err      error
		)

		groupConfig := config.NewUpstreamGroup(group, cfg, upstreams)

		switch cfg.Strategy {
		case config.UpstreamStrategyParallelBest:
			fallthrough
		case config.UpstreamStrategyRandom:
			upstream, err = NewParallelBestResolver(ctx, groupConfig, bootstrap)
		case config.UpstreamStrategyStrict:
			upstream, err = NewStrictResolver(ctx, groupConfig, bootstrap)
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("group %s: %w", group, err))

			continue
		}

		branches[group] = upstream
	}

	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	return branches, nil
}

func (r *UpstreamTreeResolver) Name() string {
	return r.String()
}

func (r *UpstreamTreeResolver) String() string {
	result := make([]string, 0, len(r.branches))

	for group, res := range r.branches {
		result = append(result, fmt.Sprintf("%s (%s)", group, res.Type()))
	}

	return fmt.Sprintf("%s upstreams %q", upstreamTreeResolverType, strings.Join(result, ", "))
}

func (r *UpstreamTreeResolver) EnableClientDNSResolver(ctx context.Context) {
	r.internalEnableClientDNSResolver()
	log.FromCtx(ctx).Info("client-specific DNS resolver groups enabled")
}

func (r *UpstreamTreeResolver) internalEnableClientDNSResolver() {
	r.status.lock.Lock()
	defer r.status.lock.Unlock()

	r.status.enableTimer.Stop()
	r.status.enabled = true
	r.status.disabledGroups = []string{}
}

func (r *UpstreamTreeResolver) DisableClientDNSResolver(
	ctx context.Context, duration time.Duration, disableGroups []string,
) error {
	s := r.status
	s.lock.Lock()
	defer s.lock.Unlock()

	s.enableTimer.Stop()

	allGroups := r.clientSpecificGroups()
	if len(disableGroups) == 0 {
		s.disabledGroups = allGroups
	} else {
		for _, group := range disableGroups {
			i := sort.SearchStrings(allGroups, group)
			if i >= len(allGroups) || allGroups[i] != group {
				return fmt.Errorf("group '%s' is unknown", group)
			}
		}

		s.disabledGroups = disableGroups
		sort.Strings(s.disabledGroups)
	}

	s.enabled = false
	s.disableEnd = time.Now().Add(duration)

	groups := strings.Join(s.disabledGroups, "; ")
	if duration == 0 {
		log.FromCtx(ctx).Infof("disable client-specific DNS resolver groups '%s'", log.EscapeInput(groups))
	} else {
		log.FromCtx(ctx).Infof("disable client-specific DNS resolver groups for %s: '%s'", duration,
			log.EscapeInput(groups))

		s.enableTimer = time.AfterFunc(duration, func() {
			r.internalEnableClientDNSResolver()
			log.Log().Info("client-specific DNS resolver groups enabled again")
		})
	}

	return nil
}

func (r *UpstreamTreeResolver) ClientDNSResolverStatus() api.BlockingStatus {
	var autoEnableDuration time.Duration

	r.status.lock.RLock()
	defer r.status.lock.RUnlock()

	if !r.status.enabled && r.status.disableEnd.After(time.Now()) {
		autoEnableDuration = time.Until(r.status.disableEnd)
	}

	return api.BlockingStatus{
		Enabled:         r.status.enabled,
		DisabledGroups:  r.status.disabledGroups,
		AutoEnableInSec: int(autoEnableDuration.Seconds()),
	}
}

func (r *UpstreamTreeResolver) clientSpecificGroups() []string {
	groups := make([]string, 0, len(r.branches))
	for group := range r.branches {
		if group != upstreamDefaultCfgName {
			groups = append(groups, group)
		}
	}

	sort.Strings(groups)

	return groups
}

func (r *UpstreamTreeResolver) isClientDNSResolverGroupDisabled(group string) bool {
	r.status.lock.RLock()
	defer r.status.lock.RUnlock()

	if r.status.enabled {
		return false
	}

	i := sort.SearchStrings(r.status.disabledGroups, group)

	return i < len(r.status.disabledGroups) && r.status.disabledGroups[i] == group
}

func (r *UpstreamTreeResolver) Resolve(ctx context.Context, request *model.Request) (*model.Response, error) {
	ctx, logger := r.log(ctx)

	group := r.upstreamGroupByClient(logger, request)

	// delegate request to group resolver
	logger.WithField("resolver", fmt.Sprintf("%s (%s)", group, r.branches[group].Type())).Debug("delegating to resolver")

	resp, err := r.branches[group].Resolve(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("upstream resolution failed for group '%s': %w", group, err)
	}

	return resp, nil
}

func (r *UpstreamTreeResolver) upstreamGroupByClient(logger *logrus.Entry, request *model.Request) string {
	groups := make([]string, 0, len(r.branches))
	clientIP := request.ClientIP.String()

	// try IP
	if _, exists := r.branches[clientIP]; exists {
		if r.isClientDNSResolverGroupDisabled(clientIP) {
			logger.WithField("group", clientIP).Debug("client-specific DNS resolver group is disabled")

			return upstreamDefaultCfgName
		}

		return clientIP
	}

	// try client names
	for _, name := range request.ClientNames {
		for group := range r.branches {
			if r.isClientDNSResolverGroupDisabled(group) {
				continue
			}

			if util.ClientNameMatchesGroupName(group, name) {
				groups = append(groups, group)
			}
		}
	}

	// try CIDR (only if no client name matched)
	if len(groups) == 0 {
		for cidr := range r.branches {
			if r.isClientDNSResolverGroupDisabled(cidr) {
				continue
			}

			if util.CidrContainsIP(cidr, request.ClientIP) {
				groups = append(groups, cidr)
			}
		}
	}

	if len(groups) > 0 {
		if len(groups) > 1 {
			logger.WithFields(logrus.Fields{
				"clientNames": request.ClientNames,
				"clientIP":    clientIP,
				"groups":      groups,
			}).Warn("client matches multiple groups")
		}

		return groups[0]
	}

	return upstreamDefaultCfgName
}
