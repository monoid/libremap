# libremap: remap binary memory with HUGEPAGE #

It *may* improve performance for large binaries.

Call the `remap_process_binary` in the `main` function, passing a
pointer to any binary's function (`main` is an excellent candidate) as
an argument.

Please note that library has to be linked dynamically, as it has to be
loaded by system into a separate memory area.

If some of remapping stages fail, the application inevitably crashes;
you may restart it with `LIBREMAP_DISABLE` environment variable; if call the `remap_process_binary` early in the main, it will not lead to loosing data or taking lot of time.

See `./example/` for usage.

Based on idea by Alexey Milovidov.

## Environment variables ##

  * `LIBREMAP_DISABLE`: if set to any value, disables remapping at all.
