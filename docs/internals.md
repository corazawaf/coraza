# Internals of ``Coraza WAF``


## WAF Engine

Waf is the main interface used to store settings, rules and create transactions, most directives will set variables for Waf instances. A coraza implementation might have unlimited Waf instances and each Waf might process unlimited transactions.

## Transactions

Transactions are an instance of an url call for a Waf instance, transactions are created with ``wafinstance.NewTransaction()``. Transactions holds collections and configurations that may be updated using rules.

## Macro Expansion

Macro expansions are a function available for ``transactions``, a macro expansion will compile a string and provide variables data to the current context. Macro expansion is performed by running a regular expresion that will find ``%{request_headers.test}`` and replace it with it's value using:

```go
v1 := tx.GetCollection(NameToVariable("request_headers")).GetFirstString("test")
v2 := tx.MacroExpansion("%{request_headers.test}")
v1 == v2
// true
```

## Rules

Rules are triggered by ``RuleGroup.Evaluate(phase)`` based on the phase number, rules with phase 0 or ``rule.AlwaysMatch`` will always run. Rules that always run are SecMarkers or SecActions which means rules without operators.

Rules marked with a SecMarker will be used to control execution flow and tell the transaction to stop skipping rules from ``skipAfter``.

Different from ModSecurity, each rule is a unique struct in Coraza and is shared between each transaction of the same ``Waf`` instance, which means a transaction should never update any field from a Rule and all **variable** fields must be stored within the transaction instead.

Once a rule is triggered, it will follow the following flow:

1. Skip if this rule is removed for the current transaction
2. Fill the ``RULE`` variable data which contain fields from the current rule
3. Apply removed targets for this transaction
4. Compile each ``variable``, normal, counters, negations and "always match"
5. Apply transformations for each variable, match or multimatch
6. Execute the current operator for each variable
7. Continue if there was any match
8. Evaluate all non-disruptive actions
9. Evaluate chains recursively 
10. Log data if requested
11. Evaluate ``disruptive`` and ``flow`` rules

The return of this function contains each ``MatchData``, which will tell the transaction where exactly the data was matched, **Variable, Key and Value**. Maybe we should add if it was negation in the future, SecActions and SecMarkers will return a placeholder.

**Important:** Rules may update a ``Transaction`` behaviour but not a ``Waf`` instance.

### Operators

Operators are stored in ``github.com/jptosso/coraza-waf/operators`` and contains an initializer and an evaluation function. Initializers are used to apply arguments during compilation, for example, ``"@rx /\d+/"`` will run ``op.Init("/\\d+")``. ``op.Evaluate(tx, "args")`` is applied for each compiled variable and will return if the condition matches. Operators uses ``Transaction`` to create logs, capture fields and access additional variables from the transaction.

**Note:** Operators must be concurrent-friendly

### Actions

Actions are stored in ``github.com/jptosso/coraza-waf/actions`` and contains an initializer and an evaluation function, the initializers are evaluated during compilation, for example, ``id:4`` will run ``act.Init("4")``. Depending on the ``Type()`` of each action, it will run on different phases.

* **Non-Disruptive:** Do something, but that something does not and cannot affect the rule processing flow. Setting a variable, or changing its value is an example of a non-disruptive action. Non-disruptive action can appear in any rule, including each rule belonging to a chain. **Non-disruptive rules are evaluated after the rule matches some data**.
* **Flow actions:** These actions affect the rule flow (for example skip or skipAfter). Flow actions are evaluated after the rule successfully matched and will only run for the parent rule of a chain.
* **Meta-data actions:** Meta-data actions are used to provide more information about rules. Examples include id, rev, severity and msg. Meta-data rules are only initialized, they won't be evaluated, ``act.Evaluate(...)`` will never be called.

### Transformations

Transformations are simple functions to transform some string into another string. There is a special struct called ``transactions.Tools``, that contains useful "tools" required for some transformations, which are ``UnicodeMapping`` for ``utf8ToUnicode`` and ``waf.Logger`` to debug transformations. More fields may be added in the future.

**Note:** Transformations are evaluated thousands of times per transaction and they must be SUPER FAST.


## Rule Groups

Rule Groups are like Modsecurity ``Rules``, it's just a container for rules that will return the list of rules concurrent-safe and will evaluate rules based on the requested phase.

## Collections

Collections are used by Coraza to store ``Variables``, all Variables are treated as the same type, even if they map values, they are single values or arrays.

Collections are stored as a slice ``[]*Collection``, each index is assigned based on it's constant name provided by ``variables.go``. For example, if you want to get a collection you might use ``tx.GetCollection(VARIABLE_FILES)``. If you want to transform a named variable to it's constant you may use: 

```go
b, _ := NameToVariable("FILES")
tx.GetCollection(b)
```

In the following example we are showing the output for ``tx.GetCollection(VARIABLE_REQUEST_HEADERS).Data()``.

```json
{
    "user-agent": [
        "some user agent string"
    ]
}
```

Some helpers may be used for this cases, like ``tx.GetCollection(VARIABLE_REQUEST_HEADERS).GetFirstString("")``.

Variables are compiled in runtime in order to support Regex(precompiled) and XML, the function ``tx.GetField(variable, exceptions)``. Using RuleVariable.Exceptions and []exceptions might seem redundant but both are different, the list of exception is complemented from the rule. In case of Regex, ``GetField`` will use ``RuleVariable.Regex`` to match data instead of ``RuleVariable.Key``.

**Note:** Collections are not concurrent-safe, don't share transactions between routines.

## Phases

Phases are used by ``RuleGroup`` to filter between execution phases on HTTP/1.1 and HTTP/1.0.

**Phase 1: Request Headers**

This phase process theorically consists in three phases:

* Connection (```tx.ProcessConnection()```): Request address and port
* Request line (```tx.ProcessUri()```): Request URL, does not include GET arguments
* Request headers (```tx.ProcessRequestHeaders()```) Will evaluate phase 1

**Phase 2: Request Body**

This phase only runs when ```RequestBodyAcces``` is ```On```, otherwise we will skip to phase 3. This phase will do one of the following:

* Reject transaction if the request body is too long and ```RequestBodyLimitAction``` is set to ```Reject```
* If ```URLENCODED```: set POST arguments and request_Body
* If ```MULTIPART```: Parse files and set FILES variables
* If ```JSON```: Not implemented yet
* If none of the above was met and ```ForceRequestBodyVariable``` is set to true, URLENCODED will be forced

See **Body Handling** for more info.

**Phase 3: Response Headers**

**Phase 4: Response Body**

**Phase 5: Logging**

This is a special phase, it will always run but it must be handled by the client. For example, if there is any error reported by Coraza, the client must at least implement a ```defer tx.ProcessLogging()```. This phase will close handlers, save persistent collections and write audit loggers, in order to write the audit loggers the following conditions must be met:

* Transaction was marked with ```auditlog``` action
* There must be at least one audit logger (```SecAuditLog```)
* ```AuditEngine``` must be ```On``` or ```RelevantOnly```
* If ```AuditEngine``` was set to ```RelevantOnly``` the response status must match ```AuditLogRelevantStatus```

## Body handling

BodyBuffer is a struct that will manage the request or response buffer and store the data to temprary files if required. BodyBuffer will apply a few rules to decide whether to buffer the data in memory or write a temporary file, it will also return a ```Reader``` to the memory buffer or the temporary file created. Temporary files must be deleted by ```tx.ProccessLoging```.

## Persistent Collections

Not working yet.

## The ```tx.ProcessRequest(req)``` helper