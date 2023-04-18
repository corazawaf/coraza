// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"strings"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type inferredPhases byte

func (p *inferredPhases) has(phase types.RulePhase) bool {
	return (*p & (1 << phase)) != 0
}

// hasOrMinor returns true if the phase is set or any phase before it
// E.g.
// inferredPhases = 00000010 (types.PhaseRequestHeaders)
// hasOrMinor(types.PhaseRequestBody) performs:
// 00000010 & 00000001
// 00000010 & 00000010
// 00000010 & 00000100
// If any of the them is true, it returns true and stops iterating
func (p *inferredPhases) hasOrMinor(phase types.RulePhase) bool {
	for i := 1; i <= int(phase); i++ {
		if (*p & (1 << i)) != 0 {
			return true
		}
	}
	return false
}

func (p *inferredPhases) set(phase types.RulePhase) {
	*p |= 1 << phase
}

// minPhase returns the earliest phase a variable may be populated.
// NOTE: variables.Args and variables.ArgsNames should ideally be evaluated
// both in phase 1 and 2, but rules can set state in the transaction, e.g. a
// counter, which prevents evaluating any variable multiple times.
func minPhase(v variables.RuleVariable) types.RulePhase {
	switch v {
	case variables.ResponseContentType:
		return types.PhaseResponseHeaders
	case variables.UniqueID:
		return types.PhaseRequestHeaders
	case variables.ArgsCombinedSize:
		// Size changes between phase 1 and 2 so evaluate both times
		return types.PhaseRequestHeaders
	case variables.FilesCombinedSize:
		return types.PhaseRequestBody
	case variables.FullRequestLength:
		// Not populated by Coraza
		return types.PhaseRequestBody
	case variables.InboundDataError:
		// Not populated by Coraza
		return types.PhaseRequestBody
	case variables.MatchedVar:
		// MatchedVar is only for logging, not evaluation
		return types.PhaseUnknown
	case variables.MatchedVarName:
		// MatchedVar is only for logging, not evaluation
		return types.PhaseUnknown
	// MultipartBoundaryWhitespace kept for compatibility
	case variables.MultipartDataAfter:
		// Not populated by Coraza
		return types.PhaseRequestBody
	case variables.OutboundDataError:
		return types.PhaseResponseBody
	case variables.QueryString:
		return types.PhaseRequestHeaders
	case variables.RemoteAddr:
		return types.PhaseRequestHeaders
	case variables.RemoteHost:
		// Not implemented
		return types.PhaseRequestHeaders
	case variables.RemotePort:
		return types.PhaseRequestHeaders
	case variables.ReqbodyError:
		return types.PhaseRequestBody
	case variables.ReqbodyErrorMsg:
		return types.PhaseRequestBody
	case variables.ReqbodyProcessorError:
		return types.PhaseRequestBody
	case variables.ReqbodyProcessorErrorMsg:
		return types.PhaseRequestBody
	case variables.ReqbodyProcessor:
		// Configuration of Coraza itself, though shouldn't be used in phases
		return types.PhaseUnknown
	case variables.RequestBasename:
		return types.PhaseRequestHeaders
	case variables.RequestBody:
		return types.PhaseRequestBody
	case variables.RequestBodyLength:
		return types.PhaseRequestBody
	case variables.RequestFilename:
		return types.PhaseRequestHeaders
	case variables.RequestLine:
		return types.PhaseRequestHeaders
	case variables.RequestMethod:
		return types.PhaseRequestHeaders
	case variables.RequestProtocol:
		return types.PhaseRequestHeaders
	case variables.RequestURI:
		return types.PhaseRequestHeaders
	case variables.RequestURIRaw:
		return types.PhaseRequestHeaders
	case variables.ResponseBody:
		return types.PhaseResponseBody
	case variables.ResponseContentLength:
		return types.PhaseResponseBody
	case variables.ResponseProtocol:
		return types.PhaseResponseHeaders
	case variables.ResponseStatus:
		return types.PhaseResponseHeaders
	case variables.ServerAddr:
		// Configuration of the server itself
		return types.PhaseRequestHeaders
	case variables.ServerName:
		// Configuration of the server itself
		return types.PhaseRequestHeaders
	case variables.ServerPort:
		// Configuration of the server itself
		return types.PhaseRequestHeaders
	case variables.HighestSeverity:
		// Result of matching, not used in phaes
		return types.PhaseUnknown
	case variables.StatusLine:
		return types.PhaseResponseHeaders
	case variables.Duration:
		// If used in matching, would need to be defined for multiple inferredPhases to make sense
		return types.PhaseUnknown
	case variables.ResponseHeadersNames:
		return types.PhaseResponseHeaders
	case variables.RequestHeadersNames:
		return types.PhaseRequestHeaders
	case variables.Args:
		// Updated between headers and body
		return types.PhaseRequestBody
	case variables.ArgsGet:
		return types.PhaseRequestHeaders
	case variables.ArgsPost:
		return types.PhaseRequestBody
	case variables.ArgsPath:
		return types.PhaseRequestHeaders
	case variables.FilesSizes:
		return types.PhaseRequestBody
	case variables.FilesNames:
		return types.PhaseRequestBody
	case variables.FilesTmpContent:
		// Not populated by Coraza
		return types.PhaseRequestBody
	case variables.MultipartFilename:
		return types.PhaseRequestBody
	case variables.MultipartName:
		return types.PhaseRequestBody
	case variables.MatchedVarsNames:
		// Result of execution, not used in inferredPhases
		return types.PhaseUnknown
	case variables.MatchedVars:
		// Result of execution, not used in inferredPhases
		return types.PhaseUnknown
	case variables.Files:
		return types.PhaseRequestBody
	case variables.RequestCookies:
		return types.PhaseRequestHeaders
	case variables.RequestHeaders:
		return types.PhaseRequestHeaders
	case variables.ResponseHeaders:
		return types.PhaseResponseHeaders
	case variables.Geo:
		// Not populated by Coraza
		return types.PhaseRequestHeaders
	case variables.RequestCookiesNames:
		return types.PhaseRequestHeaders
	case variables.FilesTmpNames:
		return types.PhaseRequestBody
	case variables.ArgsNames:
		// Updated between headers and body
		return types.PhaseRequestBody
	case variables.ArgsGetNames:
		return types.PhaseRequestHeaders
	case variables.ArgsPostNames:
		return types.PhaseRequestBody
	case variables.TX:
		return types.PhaseUnknown
	case variables.Rule:
		// Shouldn't be used in phases
		return types.PhaseUnknown
	case variables.JSON:
		return types.PhaseRequestBody
	case variables.Env:
		return types.PhaseRequestHeaders
	case variables.UrlencodedError:
		return types.PhaseRequestHeaders
	case variables.ResponseArgs:
		return types.PhaseResponseBody
	case variables.ResponseXML:
		return types.PhaseResponseBody
	case variables.RequestXML:
		return types.PhaseRequestBody
	case variables.XML:
		return types.PhaseRequestBody
	case variables.MultipartPartHeaders:
		return types.PhaseRequestBody
	}

	return types.PhaseUnknown
}

// TODO(anuraaga): This is effectively lazily computing the min phase of a rule with chain the first
// time we evaluate the rule. Instead, we should do this at parse time, but this will require a
// large-ish refactoring of the parser, which adds parent rules to a rule group before preparing
// the child rules. In the meantime, only evaluating this once should allow performance to be fine.
//
// chainMinPhase is the minimum phase among all the rules in which the chained rule may match.
// We evaluate the min possible phase for each rule in the chain and we take the minimum in common
// If we reached this point, it means that the parent rule already reached its min phase.
func computeRuleChainMinPhase(r *Rule) {
	if r.ParentID_ == 0 && r.HasChain && r.chainMinPhase == types.PhaseUnknown {
		for c := r.Chain; c != nil; c = c.Chain {
			singleChainedRuleMinPhase := types.PhaseUnknown
			for _, v := range c.variables {
				min := minPhase(v.Variable)
				if min == types.PhaseUnknown {
					continue
				}
				if singleChainedRuleMinPhase == types.PhaseUnknown || min < singleChainedRuleMinPhase {
					singleChainedRuleMinPhase = min
				}
			}
			if r.chainMinPhase == types.PhaseUnknown || singleChainedRuleMinPhase > r.chainMinPhase {
				r.chainMinPhase = singleChainedRuleMinPhase
			}
		}
	}
}

func multiphaseSkipVariable(r *Rule, variable variables.RuleVariable, phase types.RulePhase) bool {
	if r.ParentID_ == 0 && (!r.HasChain || phase >= r.chainMinPhase) {
		min := minPhase(variable)
		// When multiphase evaluation is enabled, any variable is evaluated at its
		// earliest possible phase, so we make sure to skip in other phases.
		if min != types.PhaseUnknown {
			if r.HasChain {
				if min < r.chainMinPhase {
					// The variable was previously available but not evaluated yet because the
					// chain wasn't available. We evaluate once during the chainMinPhase and
					// skip the rest.
					if phase != r.chainMinPhase {
						return true
					}
				}
				// Commented out: we have to evaluate variables multiple times to give a chance to chained rules to match
				// else if min != phase {
				// 	// Chain is available, and variable gets evaluated in its phase and skip the rest.
				// 	continue
				// }
			} else {
				// For rules that have no chains, we know the variable is evaluated in its min phase and no other phases.
				if min != phase {
					return true
				}
			}
		}
	} else if r.HasChain && phase < r.chainMinPhase {
		// When multiphase evaluation is enabled, if the variable is available but the whole chain is not,
		// we don't evaluate the rule yet.
		return true
	}
	return false
}

// generateChainMatches generates matched chains based on the matchedValues. The latter provides all the variables that matched and their depth in the chain
// generateChainMatches splits them into variables chains matches.
// E.g. REQUEST_URI (chainLevel 0), REQUEST_URI (chainLevel 1), REQUEST_HEADERS (chainLevel 1), REQUEST_BODY (chainLevel 2), REQUEST_HEADERS (chainLevel 2)
// REQUEST_URI - REQUEST_URI - REQUEST_BODY
// REQUEST_URI - REQUEST_URI - REQUEST_HEADERS
// REQUEST_URI - REQUEST_HEADERS - REQUEST_BODY
// REQUEST_URI - REQUEST_HEADERS - REQUEST_HEADERS
func generateChainMatches(tx *Transaction, matchedValues []types.MatchData, currentDepth int, buildingMatchedChain []types.MatchData, matchedChainsResult *[][]types.MatchData) {

	finalDepth := matchedChainDepth(matchedValues)

	// Iterate the variables based on the chain level (first all the variables at level 0, then all the variables at level 1, etc.)
	for _, mv := range matchedValues {
		if mv.ChainLevel() == currentDepth {
			var localebuildingMatchedChain []types.MatchData
			if buildingMatchedChain == nil {
				localebuildingMatchedChain = []types.MatchData{}
			} else {
				localebuildingMatchedChain = make([]types.MatchData, len(buildingMatchedChain))
				copy(localebuildingMatchedChain, buildingMatchedChain)
			}
			localebuildingMatchedChain = append(localebuildingMatchedChain, mv)

			if mv.ChainLevel() == finalDepth {
				// We have reached the last level of the chain, we can generate the matched chains
				*matchedChainsResult = append(*matchedChainsResult, localebuildingMatchedChain)
				continue
			}
			generateChainMatches(tx, matchedValues, currentDepth+1, localebuildingMatchedChain, matchedChainsResult)
		}
	}
}

// isMultiphaseDoubleEvaluation checks if the rule already matched against the same variables.
// It avoids running more then once the relative actions (e.g. avoids incrementing the anomaly score twice).
// Currently, it is intended for chained matches because the same variables are evaluated multiple times and not
// constained to the min phase. If the same match is found, the actions of the most inner rule are skipped and the match
// is not added to matchedValues (and removed from collectiveMatchedValues)
func isMultiphaseDoubleEvaluation(tx *Transaction, phase types.RulePhase, r *Rule, collectiveMatchedValues *[]types.MatchData, mr types.MatchData) bool {
	*collectiveMatchedValues = append(*collectiveMatchedValues, mr)

	for _, matchedRule := range tx.matchedRules {
		if matchedRule.Rule().ID() == r.ParentID_ && matchedChainDepth(matchedRule.MatchedDatas()) == matchedChainDepth(*collectiveMatchedValues) {
			// This might be a double match, let's generate the chains that aready matched and the one that just matched
			// let's see if all the latter already matched.

			// generateChainMatches generates matched chains based on the matchedValues and populates matchedChains and collectiveMatchedChains variables
			var matchedChains, collectiveMatchedChains [][]types.MatchData
			generateChainMatches(tx, matchedRule.MatchedDatas(), 0, nil, &matchedChains)
			generateChainMatches(tx, *collectiveMatchedValues, 0, nil, &collectiveMatchedChains)

			// Check if a newly matched chain (part of collectiveMatchedChain) already matched
			for _, newMatchedChain := range collectiveMatchedChains {
				// if collectiveMatchedChain is inside matchedChains, then it is a double match
				if chainPartOf(newMatchedChain, matchedChains) {
					// if this point is reached, it means that these chained values already matched
					// We have to skip actions execution in order to avoid double match against the same variable and consequent double actions execution
					var res strings.Builder
					for n, m := range newMatchedChain {
						if n != 0 {
							res.WriteString(" - ")
						}
						res.WriteString(m.Variable().Name())
					}
					rid := r.ID_
					if rid == 0 {
						rid = r.ParentID_
					}
					tx.DebugLogger().Debug().Int("rule_id", rid).Int("phase", int(phase)).
						Str("matched chain", res.String()).Msg("Chain already matched, skipping actions enforcement")
					// The rule already matched against the same variables, we skip it
					// we skip this variable and remove it from the collectiveMatchedValues slice
					*collectiveMatchedValues = (*collectiveMatchedValues)[:len(*collectiveMatchedValues)-1]
					return true
				}
			}
			// if this point is reached, it means that these chained values did not match yet
			// we can continue iterating the matched values, generate new matched chains and repeat the check
			continue
		}
	}
	return false
}

// chainPartOf checks if a chain is part of a list of already matched chains
func chainPartOf(newMatchedChain []types.MatchData, matchedChains [][]types.MatchData) bool {
	for _, matchedChain := range matchedChains {
		var differentMatch bool
		for n, newMatchedValue := range newMatchedChain {
			if newMatchedValue.Variable() != matchedChain[n].Variable() || newMatchedValue.Value() != matchedChain[n].Value() {
				differentMatch = true
				break
			}
		}
		if differentMatch {
			continue
		}
		// we found a chain already matched
		return true
	}
	return false
}

// matchedChainDepth returns the depth of a matched chain returning the lowest chain level between all the the matched values
func matchedChainDepth(datas []types.MatchData) int {
	depth := 0
	for _, matchedValue := range datas {
		if matchedValue.ChainLevel() > depth {
			depth = matchedValue.ChainLevel()
		}
	}
	return depth
}
