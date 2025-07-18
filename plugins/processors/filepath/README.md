# Filepath Processor Plugin

This plugin allows transforming a path, using e.g. basename to extract the last
path element, for tag and field values. Values can be modified in place or
stored in another key.

⭐ Telegraf v1.15.0
🏷️ transformation
💻 all

## Global configuration options <!-- @/docs/includes/plugin_config.md -->

In addition to the plugin-specific configuration settings, plugins support
additional global and plugin configuration settings. These settings are used to
modify metrics, tags, and field or create aliases and configure ordering, etc.
See the [CONFIGURATION.md][CONFIGURATION.md] for more details.

[CONFIGURATION.md]: ../../../docs/CONFIGURATION.md#plugins

## Configuration

```toml @sample.conf
# Performs file path manipulations on tags and fields
[[processors.filepath]]
  ## Treat the tag value as a path and convert it to its last element, storing the result in a new tag
  # [[processors.filepath.basename]]
  #   tag = "path"
  #   dest = "basepath"

  ## Treat the field value as a path and keep all but the last element of path, typically the path's directory
  # [[processors.filepath.dirname]]
  #   field = "path"

  ## Treat the tag value as a path, converting it to its the last element without its suffix
  # [[processors.filepath.stem]]
  #   tag = "path"

  ## Treat the tag value as a path, converting it to the shortest path name equivalent
  ## to path by purely lexical processing
  # [[processors.filepath.clean]]
  #   tag = "path"

  ## Treat the tag value as a path, converting it to a relative path that is lexically
  ## equivalent to the source path when joined to 'base_path'
  # [[processors.filepath.rel]]
  #   tag = "path"
  #   base_path = "/var/log"

  ## Treat the tag value as a path, replacing each separator character in path with a '/' character. Has only
  ## effect on Windows
  # [[processors.filepath.toslash]]
  #   tag = "path"
```

## Considerations

### Processing order

This plugin processes the specified functions in the order they appear in
the configuration. One exceptition is the `stem` section which is applied first.

If you plan to apply multiple transformations to the same `tag`/`field`, bear in
mind the processing order stated above.

### Clean Automatic Invocation

Even though `clean` is provided a standalone function, it is also invoked when
using the `rel` and `dirname` functions, so there is no need to use it along
with them.

That is:

 ```toml
[[processors.filepath]]
   [[processors.filepath.dir]]
     tag = "path"
   [[processors.filepath.clean]]
     tag = "path"
 ```

Is equivalent to:

 ```toml
[[processors.filepath]]
   [[processors.filepath.dir]]
     tag = "path"
 ```

### ToSlash Platform-specific Behavior

The effects of this function are only noticeable on Windows platforms, because
of the underlying golang implementation.

## Examples

### Basename

```toml
[[processors.filepath]]
  [[processors.filepath.basename]]
    tag = "path"
```

```diff
- my_metric,path="/var/log/batch/ajob.log" duration_seconds=134 1587920425000000000
+ my_metric,path="ajob.log" duration_seconds=134 1587920425000000000
```

### Dirname

```toml
[[processors.filepath]]
  [[processors.filepath.dirname]]
    field = "path"
    dest = "folder"
```

```diff
- my_metric path="/var/log/batch/ajob.log",duration_seconds=134 1587920425000000000
+ my_metric path="/var/log/batch/ajob.log",folder="/var/log/batch",duration_seconds=134 1587920425000000000
```

### Stem

```toml
[[processors.filepath]]
  [[processors.filepath.stem]]
    tag = "path"
```

```diff
- my_metric,path="/var/log/batch/ajob.log" duration_seconds=134 1587920425000000000
+ my_metric,path="ajob" duration_seconds=134 1587920425000000000
```

### Clean

```toml
[[processors.filepath]]
  [[processors.filepath.clean]]
    tag = "path"
```

```diff
- my_metric,path="/var/log/dummy/../batch//ajob.log" duration_seconds=134 1587920425000000000
+ my_metric,path="/var/log/batch/ajob.log" duration_seconds=134 1587920425000000000
```

### Rel

```toml
[[processors.filepath]]
  [[processors.filepath.rel]]
    tag = "path"
    base_path = "/var/log"
```

```diff
- my_metric,path="/var/log/batch/ajob.log" duration_seconds=134 1587920425000000000
+ my_metric,path="batch/ajob.log" duration_seconds=134 1587920425000000000
```

### ToSlash

```toml
[[processors.filepath]]
  [[processors.filepath.rel]]
    tag = "path"
```

```diff
- my_metric,path="\var\log\batch\ajob.log" duration_seconds=134 1587920425000000000
+ my_metric,path="/var/log/batch/ajob.log" duration_seconds=134 1587920425000000000
```

## Processing paths from tail plugin

This plugin can be used together with the [tail input
plugin](../../inputs/tail/README.md) to make modifications to the `path` tag
injected for every file.

Scenario:

* A log file `/var/log/myjobs/mysql_backup.log`, containing logs for a job execution. Whenever the job ends, a line is
written to the log file following this format: `2020-04-05 11:45:21 total time execution: 70 seconds`
* We want to generate a measurement that captures the duration of the script as a field and includes the `path` as a
tag
  * We are interested in the filename without its extensions, since it might be enough information for plotting our
    execution times in a dashboard
  * Just in case, we don't want to override the original path (if for some reason we end up having duplicates we might
    want this information)

For this purpose, we will use the `tail` input plugin, the `grok` parser plugin
and the `filepath` processor.

```toml
# Performs file path manipulations on tags and fields
[[inputs.tail]]
  files = ["/var/log/myjobs/**.log"]
  data_format = "grok"
  grok_patterns = ['%{TIMESTAMP_ISO8601:timestamp:ts-"2006-01-02 15:04:05"} total time execution: %{NUMBER:duration_seconds:int}']
  name_override = "myjobs"

[[processors.filepath]]
   [[processors.filepath.stem]]
     tag = "path"
     dest = "stempath"
```

The resulting output for a job taking 70 seconds for the mentioned log file
would look like:

```text
myjobs_duration_seconds,host="my-host",path="/var/log/myjobs/mysql_backup.log",stempath="mysql_backup" 70 1587920425000000000
```
