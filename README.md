# finalProject-HanksRevenge

## Team Roles
Protocol: DNS, written in Python -> Evan
Implant: 
Beacon callback -> Shawn
Intial commands -> Audrey

## Overview

This project is a Windows implant with a custom C2 server, an operator client, and a custom communications protocol carried over DNS.  
The implant supports both standard operator tasks and more advanced post-exploitation capabilities. In addition to implementing the technical functionality, our team followed disciplined engineering practices throughout the project, including milestone planning, pull requests, code review, issue tracking, and branch-based development.

## Supported Commands

| Command | Location | Status | Notes |
| --- | --- | --- | --- |
| `help` | Python client | Implemented | Local help menu only; not sent to the implant |
| `exit` | Python client | Implemented | Closes the operator client only |
| `pending` | Python client | Implemented | Lists queued or leased tasks on the server |
| `history` | Python client | Implemented | Lists all known tasks and their latest status |
| `check <task_id>` | Python client | Implemented | Queries one queued task result by task ID |
| `inspect-token` | Implant + Python client | Implemented | Reference end-to-end command and display handler |
| `enable-privileges` | Implant + Python client | Implemented | Enables given privilege if not already enabled and if valid |
| `impersonate-token` | Implant + Python client | Implemented | Impersonates the token of given pid |
| `whoami` | Implant + Python client | Implemented | Displays the current security context of the implant |
| `hostname` | Implant + Python client | Implemented | Displays the host or computer name |
