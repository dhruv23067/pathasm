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

## Installation Steps and Running PathAsm

PathAsm is designed to require minimal setup. Download the latest source release, install the package, and launch the application.

### 1. Download PathAsm

Download the latest **Source code (ZIP)** from the PathAsm GitHub release.

Extract the downloaded ZIP file to a directory of your choice.

### 2. Open the PathAsm Directory

Open **Command Prompt** or **PowerShell** and navigate to the extracted PathAsm directory.

For example:

```powershell
cd C:\Tools\PathAsm
```

> Replace `C:\Tools\PathAsm` with the actual location where you extracted PathAsm.

### 3. Install PathAsm

From inside the PathAsm directory, run:

```powershell
pip install .
```

This will install PathAsm along with its required Python dependencies.

### 4. Launch PathAsm

After the installation completes successfully, run:

```powershell
pathasm view
```

PathAsm will start and launch the application.

### Quick Start

If PathAsm has already been downloaded and extracted, installation and startup require only:

```powershell
cd C:\Tools\PathAsm
pip install .
pathasm view
```

## PathAsm in Action

PathAsm provides a visual environment for analyzing Active Directory relationships and comparing different paths between selected graph objects. The interface is designed to make path structure, relationship types, and calculated costs easier to inspect and interpret.

### Interactive Path Analysis

PathAsm transforms supported BloodHound / SharpHound relationships into graph objects and applies contextual weights to each relationship. Users can select a source and destination to explore the available paths between them.
<img width="903" height="313" alt="2" src="https://github.com/user-attachments/assets/b5189527-f10c-40a4-955f-408104013b33" />

### Shortest vs. Weighted Path

PathAsm evaluates paths using two approaches: a traditional shortest path, which minimizes hop count, and a weighted path, which minimizes the cumulative modeled cost of the relationships along the route.

This comparison helps highlight situations where the structurally shortest path differs from the path produced by PathAsm's contextual scoring model.
<img width="1850" height="1027" alt="3" src="https://github.com/user-attachments/assets/020ac1b2-d1d2-4783-afd2-ffef3fa32547" />


<img width="1852" height="882" alt="4" src="https://github.com/user-attachments/assets/83f898b2-8e5b-4865-a3f8-8a5277a03b5c" />



