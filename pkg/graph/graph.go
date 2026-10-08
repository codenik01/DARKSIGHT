package graph

import (
	"sync"
	"time"
)

// NodeType represents categories of nodes in the asset graph.
type NodeType string

const (
	NodeTarget    NodeType = "TARGET"
	NodeHost      NodeType = "HOST"
	NodeService   NodeType = "SERVICE"
	NodeTech      NodeType = "TECH"
	NodeEndpoint  NodeType = "ENDPOINT"
	NodeParameter NodeType = "PARAMETER"
)

// Node represents an individual asset entity.
type Node struct {
	ID         string                 `json:"id"`
	Type       NodeType               `json:"type"`
	Label      string                 `json:"label"`
	Properties map[string]interface{} `json:"properties"`
	CreatedAt  time.Time              `json:"created_at"`
}

// Edge represents a directional relationship between nodes.
type Edge struct {
	SourceID string    `json:"source_id"`
	TargetID string    `json:"target_id"`
	Relation string    `json:"relation"` // e.g. RESOLVES_TO, EXPOSES, DETECTED
	Weight   float64   `json:"weight"`
	CreatedAt time.Time `json:"created_at"`
}

// AssetGraph maintains in-memory and persistent node-edge relationships.
type AssetGraph struct {
	mu    sync.RWMutex
	Nodes map[string]Node        `json:"nodes"`
	Edges []Edge                 `json:"edges"`
	Adjacency map[string][]string `json:"adjacency"` // SourceID -> [TargetIDs]
}

func NewAssetGraph() *AssetGraph {
	return &AssetGraph{
		Nodes:     make(map[string]Node),
		Edges:     make([]Edge, 0),
		Adjacency: make(map[string][]string),
	}
}

// AddNode adds or updates a node in the asset graph.
func (g *AssetGraph) AddNode(n Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now()
	}
	if n.Properties == nil {
		n.Properties = make(map[string]interface{})
	}
	g.Nodes[n.ID] = n
}

// AddEdge connects two nodes with a relation.
func (g *AssetGraph) AddEdge(sourceID, targetID, relation string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	edge := Edge{
		SourceID:  sourceID,
		TargetID:  targetID,
		Relation:  relation,
		Weight:    1.0,
		CreatedAt: time.Now(),
	}
	g.Edges = append(g.Edges, edge)
	g.Adjacency[sourceID] = append(g.Adjacency[sourceID], targetID)
}

// GetNodesByType returns all nodes matching a specific category.
func (g *AssetGraph) GetNodesByType(nodeType NodeType) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []Node
	for _, n := range g.Nodes {
		if n.Type == nodeType {
			result = append(result, n)
		}
	}
	return result
}

// GetConnectedNodes returns nodes directly linked from a source node.
func (g *AssetGraph) GetConnectedNodes(sourceID string) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()

	targetIDs, ok := g.Adjacency[sourceID]
	if !ok {
		return nil
	}

	var result []Node
	for _, tid := range targetIDs {
		if n, exists := g.Nodes[tid]; exists {
			result = append(result, n)
		}
	}
	return result
}

// Summary returns high-level node count statistics.
func (g *AssetGraph) Summary() map[string]int {
	g.mu.RLock()
	defer g.mu.RUnlock()

	summary := make(map[string]int)
	for _, n := range g.Nodes {
		summary[string(n.Type)]++
	}
	summary["TOTAL_EDGES"] = len(g.Edges)
	return summary
}
