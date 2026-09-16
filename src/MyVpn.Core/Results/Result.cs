namespace MyVpn.Core.Results;

/// <summary>Outcome of an operation that produces no value.</summary>
public sealed class Result
{
    private Result(bool isSuccess, MyVpnError? error)
    {
        IsSuccess = isSuccess;
        Error = error;
    }

    public bool IsSuccess { get; }

    public bool IsFailure => !IsSuccess;

    public MyVpnError? Error { get; }

    public static Result Ok() => new(true, null);

    public static Result Fail(MyVpnError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new Result(false, error);
    }

    public static Result Fail(string code, string messageKey, ErrorSeverity severity = ErrorSeverity.Error,
        string? technicalDetail = null) =>
        Fail(new MyVpnError(code, messageKey, severity, technicalDetail));

    public static Result<T> Ok<T>(T value) => Result<T>.Ok(value);

    public static Result<T> Fail<T>(MyVpnError error) => Result<T>.Fail(error);

    public static Result<T> Fail<T>(string code, string messageKey,
        ErrorSeverity severity = ErrorSeverity.Error, string? technicalDetail = null) =>
        Result<T>.Fail(new MyVpnError(code, messageKey, severity, technicalDetail));
}

/// <summary>Outcome of an operation that produces a <typeparamref name="T"/>.</summary>
public sealed class Result<T>
{
    private readonly T? _value;

    private Result(bool isSuccess, T? value, MyVpnError? error)
    {
        IsSuccess = isSuccess;
        _value = value;
        Error = error;
    }

    public bool IsSuccess { get; }

    public bool IsFailure => !IsSuccess;

    public MyVpnError? Error { get; }

    /// <summary>
    /// The produced value. Throws when the result is a failure, so that a failure can
    /// never be silently observed as a default value.
    /// </summary>
    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException(
            $"Cannot read Value of a failed Result: {Error?.Code ?? "unknown"}.");

    /// <summary>Value if successful, otherwise <paramref name="fallback"/>.</summary>
    public T ValueOr(T fallback) => IsSuccess ? _value! : fallback;

    public bool TryGetValue(out T value)
    {
        value = _value!;
        return IsSuccess;
    }

    public static Result<T> Ok(T value) => new(true, value, null);

    public static Result<T> Fail(MyVpnError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new Result<T>(false, default, error);
    }

    public Result<TOut> Map<TOut>(Func<T, TOut> map)
    {
        ArgumentNullException.ThrowIfNull(map);
        return IsSuccess ? Result<TOut>.Ok(map(_value!)) : Result<TOut>.Fail(Error!);
    }

    public Result<TOut> Bind<TOut>(Func<T, Result<TOut>> bind)
    {
        ArgumentNullException.ThrowIfNull(bind);
        return IsSuccess ? bind(_value!) : Result<TOut>.Fail(Error!);
    }

    public Result ToResult() => IsSuccess ? Result.Ok() : Result.Fail(Error!);
}
