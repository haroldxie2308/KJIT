//! Strongly connected components of the body word graph (rule 6, A22).
//!
//! The verifier's own implementation: it shares nothing with the translator's
//! block-graph computation (`shared::trans::cfg::body_components`), so the two
//! must agree on the edge set of docs/pipeline.md, "Budgeted back-edges (A22)", and
//! nothing else.

use crate::shared::platform::{SharedAllocError, SharedVec, GFP_KERNEL};

const UNSET: usize = usize::MAX;

fn filled(count: usize, value: usize) -> Result<SharedVec<usize>, SharedAllocError> {
    let mut out = SharedVec::with_capacity(count, GFP_KERNEL)?;
    for _ in 0..count {
        out.push(value, GFP_KERNEL)?;
    }
    Ok(out)
}

/// Tarjan's algorithm with an explicit stack (the kernel stack is small): the
/// component id of every node of the graph on `0..count` whose `slot`-th
/// successor of `node` is `successor(node, slot)` (`None`: no more). Two nodes
/// share an id iff each reaches the other. O(nodes + edges) time, O(nodes)
/// memory.
pub(super) fn components(
    count: usize,
    successor: impl Fn(usize, usize) -> Option<usize>,
) -> Result<SharedVec<usize>, SharedAllocError> {
    // Discovery number, lowest discovery number reachable, component id (`UNSET`
    // while the node is unvisited or still on the Tarjan stack).
    let mut number = filled(count, UNSET)?;
    let mut low = filled(count, 0)?;
    let mut component = filled(count, UNSET)?;
    // Tarjan stack and call stack (node, next successor slot): at most one entry
    // per node each, `*_len` their heights.
    let mut open = filled(count, 0)?;
    let mut open_len = 0;
    let mut calls = filled(count, 0)?;
    let mut call_slots = filled(count, 0)?;
    let mut calls_len;
    let mut discovered = 0;
    let mut finished = 0;

    for root in 0..count {
        if number[root] != UNSET {
            continue;
        }
        number[root] = discovered;
        low[root] = discovered;
        discovered += 1;
        open[open_len] = root;
        open_len += 1;
        calls[0] = root;
        call_slots[0] = 0;
        calls_len = 1;

        while calls_len > 0 {
            let node = calls[calls_len - 1];
            let slot = call_slots[calls_len - 1];
            if let Some(next) = successor(node, slot) {
                call_slots[calls_len - 1] += 1;
                if number[next] == UNSET {
                    number[next] = discovered;
                    low[next] = discovered;
                    discovered += 1;
                    open[open_len] = next;
                    open_len += 1;
                    calls[calls_len] = next;
                    call_slots[calls_len] = 0;
                    calls_len += 1;
                } else if component[next] == UNSET {
                    // On the Tarjan stack: part of the current search tree.
                    low[node] = low[node].min(number[next]);
                }
                continue;
            }
            calls_len -= 1;
            if low[node] == number[node] {
                loop {
                    open_len -= 1;
                    let member = open[open_len];
                    component[member] = finished;
                    if member == node {
                        break;
                    }
                }
                finished += 1;
            }
            if calls_len > 0 {
                let parent = calls[calls_len - 1];
                low[parent] = low[parent].min(low[node]);
            }
        }
    }
    Ok(component)
}

#[cfg(test)]
mod tests {
    use super::components;

    #[test]
    fn components_group_mutually_reachable_nodes_only() {
        // 0 -> 1 -> 2 -> 1, 2 -> 3, 3 -> 3: {0}, {1, 2}, {3}.
        let edges: [&[usize]; 4] = [&[1], &[2], &[1, 3], &[3]];
        let ids = components(4, |node, slot| edges[node].get(slot).copied()).unwrap();
        assert_eq!(ids[1], ids[2]);
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[3], ids[1]);
        assert_ne!(ids[0], ids[3]);
    }

    /// The search is iterative: a path of 300000 nodes would overflow a recursive
    /// one's stack.
    #[test]
    fn a_very_long_path_does_not_recurse() {
        const NODES: usize = 300_000;
        let open = components(NODES, |node, slot| {
            (slot == 0 && node + 1 < NODES).then_some(node + 1)
        })
        .unwrap();
        assert_ne!(open[0], open[NODES - 1]);
        let closed = components(NODES, |node, slot| match slot {
            0 => Some((node + 1) % NODES),
            _ => None,
        })
        .unwrap();
        assert!(closed.iter().all(|&component| component == closed[0]));
    }
}
