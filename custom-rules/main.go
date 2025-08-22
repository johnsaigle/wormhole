package main

import (
	"github.com/mgechev/revive/cli"
	"github.com/mgechev/revive/lint"
	"github.com/mgechev/revive/revivelib"
)

func main() {
	// Create our custom rules
	alreadyLockedRule := &AlreadyLockedRule{}
	chainIDValidationRule := &ChainIDValidationRule{}

	// Run revive with our custom rules added
	cli.RunRevive(
		revivelib.NewExtraRule(alreadyLockedRule, lint.RuleConfig{}),
		revivelib.NewExtraRule(chainIDValidationRule, lint.RuleConfig{}),
	)
}
