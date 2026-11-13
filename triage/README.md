# Security slice triage

Slice 4 covers three SpotBugs findings and six PMD findings. File/line references below are from `main` (`d397bb1`), before edits, under `backend/src/main/java/team/projectpulse/`.

## Project decisions

| Decision | Choice | Checkable reason | Recorded in |
|---|---|---|---|
| D1: EI_EXPOSE_REP, EI_EXPOSE_REP2 (219) | Turn off | Entities expose managed relationships and collections; controllers/services retain injected Spring beans; DTOs and template beans pass mutable data without promising immutable snapshots. Copying managed entities or injected collaborators would change identity/lifecycle semantics. DTO mutability remains a review concern at trust boundaries. This chooses a mutable application model, rather than claiming all 219 findings are false positives. | `backend/config/spotbugs-exclude.xml` |
| D2: UncommentedEmptyConstructor, UnnecessaryConstructor (40) | Turn off | Explicit public no-arg constructors occur on JPA entities (`DocumentSectionLock`, `Rating`, etc.) and response beans (`PeerEvaluationAverage`). Framework construction and future additional constructors make automatic deletion/visibility changes unsafe. Redundant declarations on ordinary beans are a style cost the project accepts. | `backend/config/pmd-ruleset.xml` |
| D3: ControlStatementBraces (30) | Enforce | Null guards, lock checks, collection membership updates, and scheduled-reminder branches should retain an unambiguous body when edited. Add braces to all 30 sites, preserving existing statements and conditions. | Source files; comment in PMD ruleset |
| D4: GuardLogStatement (4) | Enforce | SLF4J placeholders defer formatting, but argument evaluation still calls `getName`, entity getters, `size`, and result accessors when logging is disabled. Guard the four flagged calls with the corresponding enabled check; preserve levels/messages. | `AuthController`, `ReminderService`, `WeeklyReminderScheduler`, `DocumentTemplateRegistry`; comment in PMD ruleset |

These four choices were proposed by the agent and explicitly approved by the student before configuration changes.

## My slice

| Original file:line | Rule | Verdict | Recorded as | Reason |
|---|---|---|---|---|
| `security/AuthService.java:35` | NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE | Real at the public method boundary | Fix `7674888`; `PrincipalValidationTest` | `Authentication.getPrincipal()` may return null; casting null succeeds and dereferencing it fails. Check for `MyUserPrincipal` and reject missing/unsupported principals with `BadCredentialsException` before converters/token creation. |
| `security/JwtProvider.java:38` | NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE | Real at the public method boundary | Fix `7674888`; `PrincipalValidationTest` | The same nullable principal is dereferenced while building the userId claim. Validate once and reuse the bound principal before invoking the encoder. |
| `security/SecurityConfiguration.java:130` | CT_CONSTRUCTOR_THROW | Not worth it | Constructor-local `@SuppressFBWarnings` with justification, `7674888` | RSA lookup can throw during construction. The finalizer attack requires an untrusted subclass executing in this JVM; Pulse loads trusted application configuration, not user-supplied classes. Keep fail-fast RSA startup. A final class would break the existing default Spring configuration proxy; an empty finalizer would introduce obsolete lifecycle code. This is an accepted threat-model tradeoff, not a claim that constructors cannot throw. |
| `security/AuthService.java:39` | LiteralsFirstInComparisons | Real rule violation | Fix `7674888` | Put the known non-null `"student"` literal first. This fixes that comparison only; it does not establish that null roles are valid throughout login. |
| `security/JwtProvider.java:30` | LambdaCanBeMethodReference | Real maintainability finding | Fix `7674888` | `GrantedAuthority::getAuthority` expresses precisely the existing mapping. It does not make nullable authorities non-null. |
| `security/JwtProvider.java:38` | UselessParentheses | Real maintainability finding | Fix `7674888` | Replace the nested cast/dereference with the validated pattern variable; no needed grouping is lost. |
| `security/SecurityConfiguration.java:317` | LambdaCanBeMethodReference | Real maintainability finding | Fix `7674888` | `AbstractHttpConfigurer::disable` retains the existing CSRF policy and return behavior. |
| `system/StatusCode.java:3` | InstantiableUtilityClass | Real API-design finding | Fix `7674888` | The class contains only constants, with no framework/entity role. A private constructor and final class prevent meaningless instances/subclasses without changing the constants. |
| `user/UserController.java:3` | UnnecessaryImport | Real maintainability finding | Fix `7674888` | `UserDetails` is not referenced in this controller; remove the import. |

The two null-principal tests exercise the public methods with a real Spring `UsernamePasswordAuthenticationToken` containing a null principal. They demonstrate a method-level robustness bug. They do **not** demonstrate that the current successful HTTP Basic authentication flow produces null principals or that a remote attacker can reach this state.

## The bug I showed

Test-first commit: `3ec0037` adds `PrincipalValidationTest` before any production changes. Fix commit: `7674888`.

Command from `backend/`: `sh ./mvnw -B -ntp test -Dtest=PrincipalValidationTest`.

Both tests initially fail: expected `BadCredentialsException`, received `NullPointerException` at the exact principal dereferences named by SpotBugs. Both pass after the fix, and verify that converters/encoder are not invoked on rejection. Evidence excerpts are in `evidence/`; the original-source failure was also reproduced in an isolated temporary copy using Java 21, matching the passing run.

## Additional gate repair

Adding D3 braces in `UserUtils.getUserId` changed the generated names of its other lambda methods, so three pre-existing `getAuthority()` warnings no longer matched their exact-name baseline entries, even on Java 21. Rather than add/rename baseline entries or suppress new findings, make the two `ROLE_instructor` comparisons literal-first and the requested-role comparison explicitly reject a null requested role. Remove the three old lambda entries and the now-resolved PMD `UserUtils=LiteralsFirstInComparisons` entry. The remaining `getAuthentication()` warnings are outside this slice and remain baselined.

## The baselines

| Measurement | Before | After |
|---|---:|---:|
| SpotBugs Match elements | 237 | 12 |
| PMD individual report findings covered | 130 | 48 |
| PMD class/rule pairs in properties file | 101 | 37 |
| PMD class property lines | 68 | 29 |

The assignment's 130 counts individual PMD violations; one class/rule pair can cover multiple violations. D2 removes 40, D3 fixes 30, D4 fixes 4, the Security slice fixes 6, and the additional `UserUtils` repair fixes 2. SpotBugs removes 219 D1 entries, 3 Security entries, and 3 `UserUtils` entries. A semantic before/after comparison confirms no baseline entry was added or broadened.

## What the agent did

The agent inspected code and unfiltered reports, proposed D1–D4, wrote the tests before fixes, implemented the approved choices and Security fixes, ran checks, and drafted these notes. The student approved D1–D4. The agent considered and rejected making `SecurityConfiguration` final (Spring proxy incompatibility), copying JPA entities/injected services mechanically (identity/lifecycle changes), removing no-arg constructors mechanically (framework construction), and editing baseline names to conceal compiler drift (the baseline must only shrink). Those are agent reasoning choices; they are not represented as independent student rejections. No classmate's solution was consulted.

## Sources and verification limits

- [Spring Authentication API](https://docs.spring.io/spring-security/reference/7.0/api/java/org/springframework/security/core/Authentication.html): principal is nullable.
- [Spring Configuration API](https://docs.spring.io/spring-framework/docs/7.0.2/javadoc-api/org/springframework/context/annotation/Configuration.html): default configuration proxying requires a non-final class.
- [SpotBugs CT_CONSTRUCTOR_THROW](https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#ct-be-wary-of-letting-constructors-throw-exceptions-ct-constructor-throw): describes the finalizer-attack concern.

Unfiltered reports were generated from an isolated copy of `main` with empty temporary baselines: 237 SpotBugs and 130 PMD findings. The submitted baseline files were never emptied. Java 25 initially caused additional generated-lambda baseline mismatches; Java 21 was downloaded to temporary storage to match CI.

Frontend report-only checks reproduce 130 ESLint problems (128 errors, 2 warnings), 18 vue-tsc errors, and 6 Prettier files. No frontend source changed. Browser behavior, a remotely reachable null-principal exploit, and arbitrary untrusted JVM subclasses were not verified. The course's Static Analysis module text was not supplied; the assignment and primary framework/analyzer documentation were used.
