# Ethics and authorized-use statement

PrivEscalate is intended for controlled security measurement, defensive
research, education, and authorized red-team testing.

The environments reproduce publicly documented Linux privilege-escalation
patterns inside Docker containers. They do not disclose zero-day
vulnerabilities. Ground-truth exploits are included because differential
verification requires testing the declared path against vulnerable and fixed
containers.

Do not use this artifact against systems without explicit authorization. Run
the benchmark on an isolated host, review each scenario's `run_config.json`,
and avoid exposing container SSH ports to untrusted networks. Docker shares
the host kernel, so users should apply normal container-security precautions.

Security issues in the artifact should be reported privately to the authors
through the contact channel associated with the final paper or public
repository.
