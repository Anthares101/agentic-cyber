# Agentic Cyber

The root `CLAUDE.md` has information about hacking methodology and different guidelines. Also, there are some custom skills loaded into the project and dedicated agents.

## scope-recon agent

During the reconnaissance phase, launch this agent first: "Run scope-recon for Acme Corp, subsidiaries in scope". The agent will generate the file `state/scope.json`.

In case the scope is already known, provide a file to the agent and it will process it to generate `state/scope.json` from it.

## Scout pipeline

If the `state/scope.json` assets are indeed part of the assesment, run this pipeline, it is focussed on discovering the exposed perimeter of a company. It will produce a report with information about all the attack surface of the target to ease the reconnaissance phase.

![Pipeline diagram](assets/perimeter_pipeline.svg)
