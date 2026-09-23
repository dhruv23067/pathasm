## Project Description

**PathAsm** is an open-source adversarial path-analysis tool that analyzes Active Directory relationships collected through BloodHound and SharpHound. Unlike traditional shortest-path analysis, where every relationship is treated equally, PathAsm assigns dynamic costs to graph edges based on the target system, its criticality and monitoring level, and the modeled exposure of the relationship being used. It then compares conventional shortest paths with contextually weighted paths, helping security researchers understand how two structurally similar routes can have very different modeled telemetry costs. PathAsm is designed as a research and prioritization framework for authorized security assessments, purple-team exercises, and Active Directory security analysis.

## Mathematical Model

PathAsm models an Active Directory path as a weighted graph in which each relationship is assigned a **context-sensitive cost** rather than the uniform cost used by traditional shortest-path analysis.

For every traversable edge, PathAsm calculates:

$$
\text{Stealth Cost} = (\text{Base Risk} \times \text{EDR Multiplier}) + \text{Vector Exposure Weight}
$$

The three components represent different aspects of the relationship and its destination:

* **Base Risk** represents the modeled exposure of the target system. In the current model, a modern operating system has a base value of `1.5`, while a legacy or end-of-life system has a higher value of `3.5`.

* **EDR Multiplier** represents the monitoring level and criticality of the destination. A standard endpoint uses a multiplier of `1.2`, while a Domain Controller or other Tier-0 asset uses a substantially higher multiplier of `6.0`.

* **Vector Exposure Weight** represents the relationship-specific modeled telemetry cost. Different Active Directory relationships receive different weights depending on their expected exposure within the model.

For example, consider a `MemberOf` relationship with a Vector Exposure Weight of `0.5`.

For a modern member server:

$$
(1.5 \times 1.2) + 0.5 = 2.3
$$

The resulting edge cost is therefore **2.3**.

If the same relationship leads to a Tier-0 / Domain Controller:

$$
(1.5 \times 6.0) + 0.5 = 9.5
$$

The relationship itself has not changed, but its **cost changes because the destination context has changed**.

For an entire path consisting of multiple edges, PathAsm evaluates the cumulative cost:

$$
C(P) = \sum_{e \in P} C(e)
$$

where \(C(e)\) is the calculated Stealth Cost of each edge in path \(P\).

This allows PathAsm to compare two different optimization strategies:

```text id="txpmnd"
Traditional Shortest Path
        ↓
Minimize number of edges

PathAsm Weighted Path
        ↓
Minimize cumulative modeled cost
```

As a result, a path containing more graph edges may receive a lower cumulative modeled penalty than a structurally shorter path.

> **Important:** PathAsm scores are modeling inputs used for comparative path analysis. They should not be interpreted as probabilities of detection or direct measurements of EDR/SIEM visibility. Actual telemetry depends on the environment, defensive configuration, logging policies, and other operational factors.

