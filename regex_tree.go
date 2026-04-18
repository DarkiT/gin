// Package gin 提供基于 Gin 的增强上下文与相关组件。
package gin

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// methodTyp 表示 HTTP 方法在正则路由树中的位标记。
type methodTyp uint

const (
	mSTUB methodTyp = 1 << iota
	mCONNECT
	mDELETE
	mGET
	mHEAD
	mOPTIONS
	mPATCH
	mPOST
	mPUT
	mTRACE
)

var (
	mALL = mCONNECT | mDELETE | mGET | mHEAD |
		mOPTIONS | mPATCH | mPOST | mPUT | mTRACE

	methodMu = sync.RWMutex{}

	methodMap = map[string]methodTyp{
		"CONNECT": mCONNECT,
		"DELETE":  mDELETE,
		"GET":     mGET,
		"HEAD":    mHEAD,
		"OPTIONS": mOPTIONS,
		"PATCH":   mPATCH,
		"POST":    mPOST,
		"PUT":     mPUT,
		"TRACE":   mTRACE,
	}

	reverseMethodMap = map[methodTyp]string{
		mCONNECT: "CONNECT",
		mDELETE:  "DELETE",
		mGET:     "GET",
		mHEAD:    "HEAD",
		mOPTIONS: "OPTIONS",
		mPATCH:   "PATCH",
		mPOST:    "POST",
		mPUT:     "PUT",
		mTRACE:   "TRACE",
	}
)

// registerMethod 为正则路由树注册自定义 HTTP 方法。
func registerMethod(method string) methodTyp {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return 0
	}

	methodMu.Lock()
	defer methodMu.Unlock()

	if mt, ok := methodMap[method]; ok {
		return mt
	}

	n := len(methodMap)
	if n > strconv.IntSize-2 {
		panic(fmt.Sprintf("gin: max number of methods reached (%d)", strconv.IntSize))
	}

	mt := methodTyp(2 << n)
	methodMap[method] = mt
	reverseMethodMap[mt] = method
	mALL |= mt
	return mt
}

// lookupMethod 返回方法对应的位标记。
func lookupMethod(method string) (methodTyp, bool) {
	methodMu.RLock()
	defer methodMu.RUnlock()
	mt, ok := methodMap[strings.ToUpper(strings.TrimSpace(method))]
	return mt, ok
}

// nodeTyp 表示路由树节点类型。
type nodeTyp uint8

const (
	ntStatic   nodeTyp = iota // 静态段: /home
	ntRegexp                  // 正则段: /{id:[0-9]+}
	ntParam                   // 参数段: /{user}
	ntCatchAll                // 通配段: /*
)

// node 是 chi 风格正则路由树节点。
type node struct {
	rex       *regexp.Regexp
	endpoints endpoints
	prefix    string
	children  [ntCatchAll + 1]nodes
	tail      byte
	typ       nodeTyp
	label     byte
}

// endpoints 表示一个叶子节点上可用的方法处理器集合。
type endpoints map[methodTyp]*endpoint

// endpoint 表示最终落点处理器与参数元信息。
type endpoint struct {
	handler   HandlerFunc
	pattern   string
	paramKeys []string
}

func (s endpoints) value(method methodTyp) *endpoint {
	mh, ok := s[method]
	if !ok {
		mh = &endpoint{}
		s[method] = mh
	}
	return mh
}

// routeParams 记录正则路由匹配出的参数。
type routeParams struct {
	Keys   []string
	Values []string
}

// routeContext 是正则路由匹配期间的临时上下文。
type routeContext struct {
	URLParams        routeParams
	routeParams      routeParams
	routePattern     string
	methodsAllowed   []methodTyp
	methodNotAllowed bool
}

// Reset 重置临时路由上下文，复用切片容量。
func (x *routeContext) Reset() {
	x.URLParams.Keys = x.URLParams.Keys[:0]
	x.URLParams.Values = x.URLParams.Values[:0]
	x.routeParams.Keys = x.routeParams.Keys[:0]
	x.routeParams.Values = x.routeParams.Values[:0]
	x.routePattern = ""
	x.methodsAllowed = x.methodsAllowed[:0]
	x.methodNotAllowed = false
}

// InsertRoute 将一条 chi 风格 pattern 插入路由树。
func (n *node) InsertRoute(method methodTyp, pattern string, handler HandlerFunc) *node {
	var parent *node
	search := pattern

	for {
		if len(search) == 0 {
			n.setEndpoint(method, handler, pattern)
			return n
		}

		label := search[0]
		var segTail byte
		var segEndIdx int
		var segTyp nodeTyp
		var segRexpat string
		if label == '{' || label == '*' {
			segTyp, _, segRexpat, segTail, _, segEndIdx = patNextSegment(search)
		}

		prefix := ""
		if segTyp == ntRegexp {
			prefix = segRexpat
		}

		parent = n
		n = n.getEdge(segTyp, label, segTail, prefix)

		if n == nil {
			child := &node{label: label, tail: segTail, prefix: search}
			hn := parent.addChild(child, search)
			hn.setEndpoint(method, handler, pattern)
			return hn
		}

		if n.typ > ntStatic {
			search = search[segEndIdx:]
			continue
		}

		commonPrefix := longestPrefix(search, n.prefix)
		if commonPrefix == len(n.prefix) {
			search = search[commonPrefix:]
			continue
		}

		child := &node{
			typ:    ntStatic,
			prefix: search[:commonPrefix],
		}
		parent.replaceChild(search[0], segTail, child)

		n.label = n.prefix[commonPrefix]
		n.prefix = n.prefix[commonPrefix:]
		child.addChild(n, n.prefix)

		search = search[commonPrefix:]
		if len(search) == 0 {
			child.setEndpoint(method, handler, pattern)
			return child
		}

		subchild := &node{
			typ:    ntStatic,
			label:  search[0],
			prefix: search,
		}
		hn := child.addChild(subchild, search)
		hn.setEndpoint(method, handler, pattern)
		return hn
	}
}

func (n *node) addChild(child *node, prefix string) *node {
	search := prefix
	hn := child

	segTyp, _, segRexpat, segTail, segStartIdx, segEndIdx := patNextSegment(search)

	switch segTyp {
	case ntStatic:
		// noop
	default:
		if segTyp == ntRegexp {
			rex, err := regexp.Compile(segRexpat)
			if err != nil {
				panic(fmt.Sprintf("gin: invalid regexp pattern '%s' in route param", segRexpat))
			}
			child.prefix = segRexpat
			child.rex = rex
		}

		if segStartIdx == 0 {
			child.typ = segTyp

			if segTyp == ntCatchAll {
				segStartIdx = -1
			} else {
				segStartIdx = segEndIdx
			}
			if segStartIdx < 0 {
				segStartIdx = len(search)
			}
			child.tail = segTail

			if segStartIdx != len(search) {
				search = search[segStartIdx:]

				nn := &node{
					typ:    ntStatic,
					label:  search[0],
					prefix: search,
				}
				hn = child.addChild(nn, search)
			}
		} else if segStartIdx > 0 {
			child.typ = ntStatic
			child.prefix = search[:segStartIdx]
			child.rex = nil

			search = search[segStartIdx:]

			nn := &node{
				typ:   segTyp,
				label: search[0],
				tail:  segTail,
			}
			hn = child.addChild(nn, search)
		}
	}

	n.children[child.typ] = append(n.children[child.typ], child)
	n.children[child.typ].Sort()
	return hn
}

func (n *node) replaceChild(label, tail byte, child *node) {
	for i := 0; i < len(n.children[child.typ]); i++ {
		if n.children[child.typ][i].label == label && n.children[child.typ][i].tail == tail {
			n.children[child.typ][i] = child
			n.children[child.typ][i].label = label
			n.children[child.typ][i].tail = tail
			return
		}
	}
	panic("gin: replacing missing child")
}

func (n *node) getEdge(ntyp nodeTyp, label, tail byte, prefix string) *node {
	nds := n.children[ntyp]
	for i := range nds {
		if nds[i].label == label && nds[i].tail == tail {
			if ntyp == ntRegexp && nds[i].prefix != prefix {
				continue
			}
			return nds[i]
		}
	}
	return nil
}

func (n *node) setEndpoint(method methodTyp, handler HandlerFunc, pattern string) {
	if n.endpoints == nil {
		n.endpoints = make(endpoints)
	}

	paramKeys := patParamKeys(pattern)

	if method&mSTUB == mSTUB {
		n.endpoints.value(mSTUB).handler = handler
	}
	if method&mALL == mALL {
		h := n.endpoints.value(mALL)
		h.handler = handler
		h.pattern = pattern
		h.paramKeys = paramKeys

		methodMu.RLock()
		defer methodMu.RUnlock()
		for _, m := range methodMap {
			h := n.endpoints.value(m)
			h.handler = handler
			h.pattern = pattern
			h.paramKeys = paramKeys
		}
		return
	}

	h := n.endpoints.value(method)
	h.handler = handler
	h.pattern = pattern
	h.paramKeys = paramKeys
}

// FindRoute 在路由树中查找请求方法与路径对应的处理器。
func (n *node) FindRoute(rctx *routeContext, method methodTyp, path string) (*node, endpoints, HandlerFunc) {
	rctx.routePattern = ""
	rctx.routeParams.Keys = rctx.routeParams.Keys[:0]
	rctx.routeParams.Values = rctx.routeParams.Values[:0]

	rn := n.findRoute(rctx, method, path)
	if rn == nil {
		return nil, nil, nil
	}

	rctx.URLParams.Keys = append(rctx.URLParams.Keys, rctx.routeParams.Keys...)
	rctx.URLParams.Values = append(rctx.URLParams.Values, rctx.routeParams.Values...)

	if h := pickEndpoint(rn.endpoints, method); h != nil && h.pattern != "" {
		rctx.routePattern = h.pattern
		return rn, rn.endpoints, h.handler
	}

	return rn, rn.endpoints, nil
}

func (n *node) findRoute(rctx *routeContext, method methodTyp, path string) *node {
	nn := n
	search := path

	for t, nds := range nn.children {
		ntyp := nodeTyp(t)
		if len(nds) == 0 {
			continue
		}

		var xn *node
		xsearch := search

		var label byte
		if search != "" {
			label = search[0]
		}

		switch ntyp {
		case ntStatic:
			xn = nds.findEdge(label)
			if xn == nil || !strings.HasPrefix(xsearch, xn.prefix) {
				continue
			}
			xsearch = xsearch[len(xn.prefix):]

		case ntParam, ntRegexp:
			if xsearch == "" {
				if ntyp == ntRegexp {
					for _, xn = range nds {
						if xn.rex == nil || xn.hasChildren() || !xn.rex.MatchString("") {
							continue
						}

						prevKeysLen := len(rctx.routeParams.Keys)
						prevValsLen := len(rctx.routeParams.Values)
						rctx.routeParams.Values = append(rctx.routeParams.Values, "")

						if xn.isLeaf() {
							if h := pickEndpoint(xn.endpoints, method); h != nil && h.handler != nil {
								rctx.routeParams.Keys = append(rctx.routeParams.Keys, h.paramKeys...)
								return xn
							}

							for endpointMethod := range xn.endpoints {
								if endpointMethod == mALL || endpointMethod == mSTUB {
									continue
								}
								rctx.methodsAllowed = append(rctx.methodsAllowed, endpointMethod)
							}
							rctx.methodNotAllowed = true
						}

						rctx.routeParams.Keys = rctx.routeParams.Keys[:prevKeysLen]
						rctx.routeParams.Values = rctx.routeParams.Values[:prevValsLen]
					}
				}
				continue
			}

			for _, xn = range nds {
				p := strings.IndexByte(xsearch, xn.tail)

				if p < 0 {
					if xn.tail == '/' {
						p = len(xsearch)
					} else {
						continue
					}
				} else if ntyp == ntRegexp && p == 0 {
					continue
				}

				candidate := xsearch[:p]
				if ntyp == ntRegexp && xn.rex != nil {
					if xn.tail == '/' && !xn.hasChildren() && xn.rex.MatchString(xsearch) {
						p = len(xsearch)
						candidate = xsearch
					}
					if !xn.rex.MatchString(candidate) {
						continue
					}
				} else if strings.IndexByte(candidate, '/') != -1 {
					continue
				}

				prevlen := len(rctx.routeParams.Values)
				rctx.routeParams.Values = append(rctx.routeParams.Values, candidate)
				xsearch = xsearch[p:]

				if len(xsearch) == 0 {
					if xn.isLeaf() {
						if h := pickEndpoint(xn.endpoints, method); h != nil && h.handler != nil {
							rctx.routeParams.Keys = append(rctx.routeParams.Keys, h.paramKeys...)
							return xn
						}

						for endpointMethod := range xn.endpoints {
							if endpointMethod == mALL || endpointMethod == mSTUB {
								continue
							}
							rctx.methodsAllowed = append(rctx.methodsAllowed, endpointMethod)
						}
						rctx.methodNotAllowed = true
					}
				}

				fin := xn.findRoute(rctx, method, xsearch)
				if fin != nil {
					return fin
				}

				rctx.routeParams.Values = rctx.routeParams.Values[:prevlen]
				xsearch = search
			}

			rctx.routeParams.Values = append(rctx.routeParams.Values, "")

		default:
			catchAllValue := search
			if catchAllValue == "" {
				catchAllValue = "/"
			} else if catchAllValue[0] != '/' {
				catchAllValue = "/" + catchAllValue
			}
			rctx.routeParams.Values = append(rctx.routeParams.Values, catchAllValue)
			xn = nds[0]
			xsearch = ""
		}

		if xn == nil {
			continue
		}

		if len(xsearch) == 0 {
			if xn.isLeaf() {
				if h := pickEndpoint(xn.endpoints, method); h != nil && h.handler != nil {
					rctx.routeParams.Keys = append(rctx.routeParams.Keys, h.paramKeys...)
					return xn
				}

				for endpointMethod := range xn.endpoints {
					if endpointMethod == mALL || endpointMethod == mSTUB {
						continue
					}
					rctx.methodsAllowed = append(rctx.methodsAllowed, endpointMethod)
				}
				rctx.methodNotAllowed = true
			}
		}

		fin := xn.findRoute(rctx, method, xsearch)
		if fin != nil {
			return fin
		}

		if xn.typ > ntStatic && len(rctx.routeParams.Values) > 0 {
			rctx.routeParams.Values = rctx.routeParams.Values[:len(rctx.routeParams.Values)-1]
		}
	}

	return nil
}

func pickEndpoint(eps endpoints, method methodTyp) *endpoint {
	if eps == nil {
		return nil
	}
	if h := eps[method]; h != nil && h.handler != nil {
		return h
	}
	if h := eps[mALL]; h != nil && h.handler != nil {
		return h
	}
	return nil
}

func (n *node) isLeaf() bool {
	return n.endpoints != nil
}

func (n *node) hasChildren() bool {
	for _, children := range n.children {
		if len(children) > 0 {
			return true
		}
	}
	return false
}

// patNextSegment 返回下一个 pattern 段的信息。
func patNextSegment(pattern string) (nodeTyp, string, string, byte, int, int) {
	ps := strings.Index(pattern, "{")
	ws := strings.Index(pattern, "*")

	if ps < 0 && ws < 0 {
		return ntStatic, "", "", 0, 0, len(pattern)
	}

	if ps >= 0 && ws >= 0 && ws < ps {
		panic("gin: wildcard '*' must be the last pattern in a route, otherwise use a '{param}'")
	}

	tail := byte('/')

	if ps >= 0 {
		nt := ntParam

		cc := 0
		pe := ps
		for i, c := range pattern[ps:] {
			if c == '{' {
				cc++
			} else if c == '}' {
				cc--
				if cc == 0 {
					pe = ps + i
					break
				}
			}
		}
		if pe == ps {
			panic("gin: route param closing delimiter '}' is missing")
		}

		key := pattern[ps+1 : pe]
		pe++

		if pe < len(pattern) {
			tail = pattern[pe]
		}

		key, rexpat, isRegexp := strings.Cut(key, ":")
		if isRegexp {
			nt = ntRegexp
		}

		if len(rexpat) > 0 {
			if rexpat[0] != '^' {
				rexpat = "^" + rexpat
			}
			if rexpat[len(rexpat)-1] != '$' {
				rexpat += "$"
			}
		}

		return nt, key, rexpat, tail, ps, pe
	}

	if ws < len(pattern)-1 {
		key := pattern[ws+1:]
		if strings.IndexByte(key, '/') >= 0 {
			panic("gin: wildcard '*' must be the last value in a route. trim trailing text or use a '{param}' instead")
		}
		return ntCatchAll, key, "", 0, ws, len(pattern)
	}
	return ntCatchAll, "*", "", 0, ws, len(pattern)
}

// patParamKeys 提取 pattern 中所有参数名，保持顺序。
func patParamKeys(pattern string) []string {
	pat := pattern
	paramKeys := []string{}
	for {
		ptyp, paramKey, _, _, _, e := patNextSegment(pat)
		if ptyp == ntStatic {
			return paramKeys
		}
		for i := 0; i < len(paramKeys); i++ {
			if paramKeys[i] == paramKey {
				panic(fmt.Sprintf("gin: routing pattern '%s' contains duplicate param key, '%s'", pattern, paramKey))
			}
		}
		paramKeys = append(paramKeys, paramKey)
		pat = pat[e:]
	}
}

func longestPrefix(k1, k2 string) (i int) {
	for i = 0; i < min(len(k1), len(k2)); i++ {
		if k1[i] != k2[i] {
			break
		}
	}
	return
}

type nodes []*node

func (ns nodes) Sort()              { sort.Sort(ns); ns.tailSort() }
func (ns nodes) Len() int           { return len(ns) }
func (ns nodes) Swap(i, j int)      { ns[i], ns[j] = ns[j], ns[i] }
func (ns nodes) Less(i, j int) bool { return ns[i].label < ns[j].label }

func (ns nodes) tailSort() {
	for i := len(ns) - 1; i >= 0; i-- {
		if ns[i].typ > ntStatic && ns[i].tail == '/' {
			ns.Swap(i, len(ns)-1)
			return
		}
	}
}

func (ns nodes) findEdge(label byte) *node {
	num := len(ns)
	idx := 0
	i, j := 0, num-1
	for i <= j {
		idx = i + (j-i)/2
		if label > ns[idx].label {
			i = idx + 1
		} else if label < ns[idx].label {
			j = idx - 1
		} else {
			i = num
		}
	}
	if num == 0 || ns[idx].label != label {
		return nil
	}
	return ns[idx]
}
