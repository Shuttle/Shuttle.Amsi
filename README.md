# Shuttle.Amsi

Integrates with the Windows (10, 2016+) anti-malware scan interface that uses the registered provider to scan content for malware.

## Usage

```c#
var context = new AmsiContext("ApplicationName");
```

The `applicationName` argument is optional and a `Guid` will be assigned as the name if none is specified.

## Methods

```c#
public bool AmsiContext.IsAvailable();
```

Returns `true` if an AMSI provider has been registered; else `false`.  This is achieved by scanning the standard EICAR test string.

```c#
public bool HasMalware(Stream stream, string contentName);
public bool HasMalware(byte[] bytearray, string contentName);
```

Returns `true` if the `stream` or `bytearray` contains malware; else `false`.