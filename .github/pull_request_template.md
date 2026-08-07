## What and why

<!-- The defect or need, with a number where one exists. -->

## Evidence

<!-- Measured before/after, or the query that shows it. "Tests pass" is not
     evidence that the change does what the title says. -->

## Review playbook

`docs/REVIEW_PLAYBOOK.md` records defects that actually occurred here and the
questions that caught them. Which did you consider?

- [ ] **Q1** modified tests still test something (not passing for the wrong reason)
- [ ] **Q2** what this does NOT fix that the title implies it does
- [ ] **Q3** the measurement measures the thing, not a proxy
- [ ] **Q4** config the code reads exists in the deployment
- [ ] **Q5** no document trusted over the code
- [ ] **Q6** what breaks downstream when this stops being emitted
- [ ] **Q7** an operator would SEE this failing
- [ ] **Q8** a repeated class is enforced at the choke point, not just this instance
- [ ] N/A because: <!-- say why -->

## Findings from review

<!-- Tag each serious finding Q1-Q8 / new-class / self-caught, per playbook §4.
     `new-class` findings should be ADDED to the playbook in this PR. -->
