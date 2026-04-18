package main

type exportSymbol struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	File string `json:"file"`
}

type symbolFinding struct {
	Name         string `json:"name"`
	UpstreamKind string `json:"upstream_kind,omitempty"`
	LocalKind    string `json:"local_kind,omitempty"`
	Status       string `json:"status"`
	Note         string `json:"note,omitempty"`
}

type methodFinding struct {
	Name              string `json:"name"`
	LocalSignature    string `json:"local_signature,omitempty"`
	UpstreamSignature string `json:"upstream_signature,omitempty"`
	Status            string `json:"status"`
	Note              string `json:"note,omitempty"`
}

type typeFinding struct {
	Name         string `json:"name"`
	LocalType    string `json:"local_type"`
	UpstreamType string `json:"upstream_type"`
	Status       string `json:"status"`
	Note         string `json:"note,omitempty"`
}

type packageReport struct {
	UpstreamExports int             `json:"upstream_exports"`
	LocalExports    int             `json:"local_exports"`
	Synced          []symbolFinding `json:"synced"`
	Mapped          []symbolFinding `json:"mapped"`
	Missing         []symbolFinding `json:"missing"`
	LocalOnly       []symbolFinding `json:"local_only"`
}

type namedTypeReport struct {
	Synced    []typeFinding `json:"synced"`
	Divergent []typeFinding `json:"divergent"`
}

type methodReport struct {
	TypeName       string          `json:"type_name"`
	LocalMethodSet string          `json:"local_method_set"`
	UpstreamType   string          `json:"upstream_type"`
	Note           string          `json:"note,omitempty"`
	SyncedCount    int             `json:"synced_count"`
	Incompatible   []methodFinding `json:"incompatible"`
	LocalOnly      []methodFinding `json:"local_only"`
	UpstreamOnly   []methodFinding `json:"upstream_only"`
}

type report struct {
	LocalModulePath string          `json:"local_module_path"`
	LocalPackageDir string          `json:"local_package_dir"`
	UpstreamModule  string          `json:"upstream_module"`
	UpstreamVersion string          `json:"upstream_version"`
	UpstreamDir     string          `json:"upstream_dir"`
	Package         packageReport   `json:"package"`
	NamedTypes      namedTypeReport `json:"named_types"`
	Methods         []methodReport  `json:"methods"`
}
