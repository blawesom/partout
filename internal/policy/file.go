package policy

import (
	pb "github.com/blawesom/partout/internal/proto"
)

// FileAction builds a policy.Action for a file operation. class is the
// action class (file.read / file.write / file.perm) and path is the target
// path. command_regex on a rule matches against the path, so operators can
// scope rules to path prefixes (e.g. "^/etc/").
func FileAction(class, path string) Action {
	return Action{
		ActionClass: class,
		Path:        path,
		CommandLine: path,
	}
}

// FileOpClass maps a FileOpKind to its policy action class (arch A6).
// Kinds that need no policy check (e.g. upload abort, which only removes an
// agent-side temp file) return ok=false.
func FileOpClass(kind pb.FileOpKind) (class string, ok bool) {
	switch kind {
	case pb.FileOpKind_FILE_OP_STAT,
		pb.FileOpKind_FILE_OP_LIST,
		pb.FileOpKind_FILE_OP_DOWNLOAD:
		return ActionFileRead, true
	case pb.FileOpKind_FILE_OP_UPLOAD_BEGIN,
		pb.FileOpKind_FILE_OP_UPLOAD_CHUNK,
		pb.FileOpKind_FILE_OP_UPLOAD_COMMIT,
		pb.FileOpKind_FILE_OP_EDIT_CAS:
		return ActionFileWrite, true
	case pb.FileOpKind_FILE_OP_SET_PERM:
		return ActionFilePerm, true
	default:
		return "", false
	}
}