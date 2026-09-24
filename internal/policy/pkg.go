package policy

import (
	pb "github.com/blawesom/partout/internal/proto"
)

// PkgAction builds a policy.Action for a package operation. class is the
// action class (pkg.list / pkg.apply). command_regex on a rule matches
// against the command line, so operators can scope rules per distro
// backend (e.g. "^apt-get " or "^dnf ").
func PkgAction(class, cmdLine string) Action {
	return Action{
		ActionClass: class,
		CommandLine: cmdLine,
	}
}

// PkgOpClass maps a PkgOpKind to its policy action class.
// List is read-only; Apply is a system mutation.
func PkgOpClass(kind pb.PkgOpKind) (class string, ok bool) {
	switch kind {
	case pb.PkgOpKind_PKG_LIST_UPDATES:
		return ActionPkgList, true
	case pb.PkgOpKind_PKG_APPLY:
		return ActionPkgApply, true
	default:
		return "", false
	}
}
