package main

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/mgechev/revive/lint"
)

// ChainIDValidationRule ensures that integer values are validated before being cast to vaa.ChainID
type ChainIDValidationRule struct{}

// Name returns the rule name
func (r *ChainIDValidationRule) Name() string {
	return "chain-id-validation-checker"
}

// Apply applies the rule to the given file
func (r *ChainIDValidationRule) Apply(file *lint.File, arguments lint.Arguments) []lint.Failure {
	var failures []lint.Failure

	// Walk through all nodes in the AST
	ast.Inspect(file.AST, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			failures = append(failures, r.checkChainIDCast(callExpr, file)...)
		}
		return true
	})

	return failures
}

// checkChainIDCast checks for direct vaa.ChainID casts without validation
func (r *ChainIDValidationRule) checkChainIDCast(callExpr *ast.CallExpr, file *lint.File) []lint.Failure {
	var failures []lint.Failure

	// Check if this is a vaa.ChainID type cast
	if !r.isChainIDCast(callExpr) {
		return failures
	}

	// Skip if the argument is already a constant or a known safe value
	if r.isArgSafe(callExpr) {
		return failures
	}

	// Check if we're in the same function scope as a validation call
	funcScope := r.findEnclosingFunction(callExpr, file)
	if funcScope != nil && r.hasChainIDValidation(funcScope) {
		return failures
	}

	// Report violation
	failures = append(failures, lint.Failure{
		Confidence: 0.8,
		Node:       callExpr,
		Category:   "logic",
		Failure:    "direct cast to vaa.ChainID without validation. Consider using vaa.ChainIDFromNumber() or vaa.KnownChainIDFromNumber() instead",
	})

	return failures
}

// isChainIDCast checks if a call expression is a cast to vaa.ChainID
func (r *ChainIDValidationRule) isChainIDCast(callExpr *ast.CallExpr) bool {
	switch fun := callExpr.Fun.(type) {
	case *ast.SelectorExpr:
		// vaa.ChainID(x)
		if fun.Sel != nil && fun.Sel.Name == "ChainID" {
			if ident, ok := fun.X.(*ast.Ident); ok {
				// Support both "vaa" package and direct ChainID type references
				return ident.Name == "vaa" || ident.Name == "ChainID"
			}
		}
	case *ast.Ident:
		// ChainID(x) - if imported without package prefix or local type
		return fun.Name == "ChainID"
	}
	return false
}

// isArgSafe checks if the argument to ChainID cast is safe (constant, literal, or already validated)
func (r *ChainIDValidationRule) isArgSafe(callExpr *ast.CallExpr) bool {
	if len(callExpr.Args) != 1 {
		return false
	}

	arg := callExpr.Args[0]
	switch argExpr := arg.(type) {
	case *ast.BasicLit:
		// Literal values like vaa.ChainID(1) are safe if they're integers
		// Float literals like vaa.ChainID(1.0) should still be flagged
		return argExpr.Kind == token.INT

	case *ast.Ident:
		// Constants like vaa.ChainIDSolana or vaa.GovernanceChain are safe
		name := strings.ToLower(argExpr.Name)
		return strings.Contains(name, "chainid") ||
			strings.Contains(name, "governance") ||
			strings.Contains(name, "chain") // Also allow other chain-related constants

	case *ast.SelectorExpr:
		// vaa.ChainIDSolana, vaa.GovernanceChain, etc.
		if argExpr.Sel != nil {
			selName := strings.ToLower(argExpr.Sel.Name)
			return strings.Contains(selName, "chainid") ||
				strings.Contains(selName, "governance") ||
				strings.Contains(selName, "chain") // Also allow other chain-related constants
		}

	case *ast.BinaryExpr:
		// Binary expressions with constants might be safe (e.g., const + const)
		// For now, let's be conservative and flag them - they should use validation
		return false

	case *ast.CallExpr:
		// Function calls should use validation, except for already-validated results
		// This includes array/slice access, type conversions, etc.
		return false
	}

	return false
}

// findEnclosingFunction finds the function declaration that contains the given node
func (r *ChainIDValidationRule) findEnclosingFunction(targetNode ast.Node, file *lint.File) *ast.FuncDecl {
	var enclosingFunc *ast.FuncDecl

	ast.Inspect(file.AST, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			if funcDecl.Body != nil {
				// Check if targetNode is within this function
				if r.nodeContainsTarget(funcDecl.Body, targetNode) {
					enclosingFunc = funcDecl
					return false // Stop searching
				}
			}
		}
		return true
	})

	return enclosingFunc
}

// nodeContainsTarget checks if a node contains the target node in its subtree
func (r *ChainIDValidationRule) nodeContainsTarget(container ast.Node, target ast.Node) bool {
	found := false
	ast.Inspect(container, func(n ast.Node) bool {
		if n == target {
			found = true
			return false
		}
		return true
	})
	return found
}

// hasChainIDValidation checks if a function contains calls to chain ID validation functions
func (r *ChainIDValidationRule) hasChainIDValidation(funcDecl *ast.FuncDecl) bool {
	hasValidation := false

	ast.Inspect(funcDecl, func(n ast.Node) bool {
		if callExpr, ok := n.(*ast.CallExpr); ok {
			if r.isChainIDValidationCall(callExpr) {
				hasValidation = true
				return false
			}
		}
		return true
	})

	return hasValidation
}

// isChainIDValidationCall checks if a call expression is a chain ID validation function
func (r *ChainIDValidationRule) isChainIDValidationCall(callExpr *ast.CallExpr) bool {
	switch fun := callExpr.Fun.(type) {
	case *ast.SelectorExpr:
		if fun.Sel != nil && fun.X != nil {
			funcName := fun.Sel.Name
			// Check for vaa.ChainIDFromNumber, vaa.KnownChainIDFromNumber, vaa.StringToKnownChainID
			if funcName == "ChainIDFromNumber" || funcName == "KnownChainIDFromNumber" || funcName == "StringToKnownChainID" {
				if ident, ok := fun.X.(*ast.Ident); ok && ident.Name == "vaa" {
					return true
				}
			}
		}
	}
	return false
}
