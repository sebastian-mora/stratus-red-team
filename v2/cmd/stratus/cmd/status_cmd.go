package cmd

import (
	"fmt"
	"strings"

	"github.com/datadog/stratus-red-team/v2/internal/state"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

var statusStateFilter string

func buildStatusCmd() *cobra.Command {
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Display the status of TTPs.",
		Example: strings.Join([]string{
			"stratus status",
			"stratus status aws.credential-access",
			"stratus status --state warm",
		}, "\n"),
		Args: func(cmd *cobra.Command, args []string) error {
			if _, err := parseStateFilter(statusStateFilter); err != nil {
				return err
			}
			if len(args) == 0 {
				return nil // no technique specified == all techniques
			}
			_, err := resolveTechniques(args)
			return err
		},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				techniques, _ := resolveTechniques(args)
				doFilteredStatusCmd(techniques, statusStateFilter)
			} else {
				doFilteredStatusCmd(stratus.GetRegistry().ListAttackTechniques(), statusStateFilter)
			}
		},
	}
	statusCmd.Flags().StringVarP(&statusStateFilter, "state", "", "", "Only display techniques in a specific state (cold, warm, detonated)")
	return statusCmd
}

func parseStateFilter(filter string) (stratus.AttackTechniqueState, error) {
	if filter == "" {
		return "", nil
	}
	switch state := stratus.AttackTechniqueState(strings.ToUpper(filter)); state {
	case stratus.AttackTechniqueStatusCold, stratus.AttackTechniqueStatusWarm, stratus.AttackTechniqueStatusDetonated:
		return state, nil
	default:
		return "", fmt.Errorf("invalid state %q, must be one of: cold, warm, detonated", filter)
	}
}

func doStatusCmd(techniques []*stratus.AttackTechnique) {
	doFilteredStatusCmd(techniques, "")
}

func doFilteredStatusCmd(techniques []*stratus.AttackTechnique, stateFilter string) {
	wantedState, _ := parseStateFilter(stateFilter)
	t := GetDisplayTable()
	t.AppendHeader(table.Row{"ID", "Name", "Status"})
	// Resolve the same state layout the lifecycle commands use, so that a correlation ID in the
	// environment reports on that execution rather than on the flat layout.
	stateOpts := []state.ManagerOption{state.WithReadOnlyState()}
	if subdirectory := runner.ExecutionSubdirectoryFromEnv(); subdirectory != "" {
		stateOpts = append(stateOpts, state.WithExecutionSubdirectory(subdirectory))
	}
	for i := range techniques {
		stateManager := state.NewFileSystemStateManager(techniques[i], stateOpts...)
		techniqueState := stateManager.GetTechniqueState()
		if techniqueState == "" {
			techniqueState = stratus.AttackTechniqueStatusCold
		}
		if wantedState != "" && techniqueState != wantedState {
			continue
		}
		t.AppendRow(table.Row{techniques[i].ID, techniques[i].FriendlyName, colorState(techniqueState)})
	}
	t.Render()
}

func colorState(state stratus.AttackTechniqueState) string {
	stateString := string(state)
	switch state {
	case stratus.AttackTechniqueStatusCold:
		return color.CyanString(stateString)
	case stratus.AttackTechniqueStatusWarm:
		return color.YellowString(stateString)
	case stratus.AttackTechniqueStatusDetonated:
		return color.MagentaString(stateString)
	default:
		return stateString
	}
}
