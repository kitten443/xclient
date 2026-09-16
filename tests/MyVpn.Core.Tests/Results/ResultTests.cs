using MyVpn.Core.Results;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class ResultTests
{
    [Fact]
    public void Ok_has_no_error()
    {
        var result = Result.Ok();

        result.IsSuccess.ShouldBeTrue();
        result.IsFailure.ShouldBeFalse();
        result.Error.ShouldBeNull();
    }

    [Fact]
    public void Fail_carries_the_error()
    {
        var error = new MyVpnError(ErrorCodes.ConfigInvalid, "error.settings.invalid");
        var result = Result.Fail(error);

        result.IsFailure.ShouldBeTrue();
        result.IsSuccess.ShouldBeFalse();
        result.Error.ShouldBeSameAs(error);
    }

    [Fact]
    public void Fail_from_a_code_and_message_key_builds_the_error()
    {
        var result = Result.Fail(ErrorCodes.XrayStartFailed, "error.xray.start_failed", ErrorSeverity.Critical, "detail");

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.XrayStartFailed);
        result.Error.MessageKey.ShouldBe("error.xray.start_failed");
        result.Error.Severity.ShouldBe(ErrorSeverity.Critical);
        result.Error.TechnicalDetail.ShouldBe("detail");
    }

    [Fact]
    public void Fail_rejects_a_null_error()
    {
        Should.Throw<ArgumentNullException>(() => Result.Fail(null!));
        Should.Throw<ArgumentNullException>(() => Result<int>.Fail(null!));
    }

    [Fact]
    public void Generic_ok_produces_the_value()
    {
        var result = Result.Ok(42);

        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldBe(42);
        result.ValueOr(7).ShouldBe(42);
        result.TryGetValue(out var value).ShouldBeTrue();
        value.ShouldBe(42);
    }

    [Fact]
    public void Reading_Value_of_a_failure_throws()
    {
        var result = Result<int>.Fail(new MyVpnError(ErrorCodes.NotFound, "error.not_found"));

        var exception = Should.Throw<InvalidOperationException>(() => _ = result.Value);
        exception.Message.ShouldContain(ErrorCodes.NotFound);
    }

    [Fact]
    public void ValueOr_returns_the_fallback_for_a_failure()
    {
        var result = Result<int>.Fail(new MyVpnError(ErrorCodes.NotFound, "error.not_found"));

        result.ValueOr(7).ShouldBe(7);
    }

    [Fact]
    public void TryGetValue_reports_failure_and_returns_default()
    {
        var result = Result<int>.Fail(new MyVpnError(ErrorCodes.NotFound, "error.not_found"));

        result.TryGetValue(out var value).ShouldBeFalse();
        value.ShouldBe(0);
    }

    [Fact]
    public void Fail_from_a_code_builds_a_typed_error()
    {
        var result = Result.Fail<int>(ErrorCodes.InvalidArgument, "error.invalid_argument", ErrorSeverity.Warning);

        result.IsFailure.ShouldBeTrue();
        result.Error!.Code.ShouldBe(ErrorCodes.InvalidArgument);
        result.Error.Severity.ShouldBe(ErrorSeverity.Warning);
    }

    [Fact]
    public void Map_projects_a_successful_value()
    {
        var result = Result.Ok(21).Map(v => v * 2);

        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldBe(42);
    }

    [Fact]
    public void Map_propagates_the_original_error_without_invoking_the_mapper()
    {
        var error = new MyVpnError(ErrorCodes.NotFound, "error.not_found");
        var invoked = false;

        var mapped = Result<int>.Fail(error).Map(v =>
        {
            invoked = true;
            return v.ToString();
        });

        invoked.ShouldBeFalse();
        mapped.IsFailure.ShouldBeTrue();
        mapped.Error.ShouldBeSameAs(error);
    }

    [Fact]
    public void Bind_projects_a_successful_value()
    {
        var result = Result.Ok(21).Bind(v => Result<string>.Ok("value " + v));

        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldBe("value 21");
    }

    [Fact]
    public void Bind_propagates_the_original_error_without_invoking_the_binder()
    {
        var error = new MyVpnError(ErrorCodes.NotFound, "error.not_found");
        var invoked = false;

        var bound = Result<int>.Fail(error).Bind(v =>
        {
            invoked = true;
            return Result<string>.Ok(v.ToString());
        });

        invoked.ShouldBeFalse();
        bound.IsFailure.ShouldBeTrue();
        bound.Error.ShouldBeSameAs(error);
    }

    [Fact]
    public void Bind_can_return_a_failure_of_its_own()
    {
        var inner = new MyVpnError(ErrorCodes.ConfigInvalid, "error.settings.invalid");

        var result = Result.Ok(1).Bind(_ => Result<int>.Fail(inner));

        result.IsFailure.ShouldBeTrue();
        result.Error.ShouldBeSameAs(inner);
    }

    [Fact]
    public void Map_and_Bind_reject_null_callbacks()
    {
        Should.Throw<ArgumentNullException>(() => Result.Ok(1).Map<int>(null!));
        Should.Throw<ArgumentNullException>(() => Result.Ok(1).Bind<int>(null!));
    }

    [Fact]
    public void ToResult_preserves_success_and_failure()
    {
        Result.Ok(1).ToResult().IsSuccess.ShouldBeTrue();

        var error = new MyVpnError(ErrorCodes.NotFound, "error.not_found");
        var failed = Result<int>.Fail(error).ToResult();

        failed.IsFailure.ShouldBeTrue();
        failed.Error.ShouldBeSameAs(error);
    }
}

public sealed class MyVpnErrorTests
{
    [Fact]
    public void Defaults_are_sane()
    {
        var error = new MyVpnError("code", "key");

        error.Severity.ShouldBe(ErrorSeverity.Error);
        error.TechnicalDetail.ShouldBeNull();
        error.RemediationKey.ShouldBeNull();
        error.Arguments.ShouldBeEmpty();
    }

    [Fact]
    public void Error_severity_ordering_is_documented()
    {
        ((int)ErrorSeverity.Warning).ShouldBe(0);
        ((int)ErrorSeverity.Error).ShouldBe(1);
        ((int)ErrorSeverity.Critical).ShouldBe(2);
        ((int)ErrorSeverity.Critical > (int)ErrorSeverity.Error).ShouldBeTrue();
    }

    [Fact]
    public void WithArg_returns_a_copy_and_does_not_mutate_the_original()
    {
        var original = new MyVpnError("code", "key");
        var extended = original.WithArg("port", "443");

        extended.Arguments["port"].ShouldBe("443");
        original.Arguments.ShouldBeEmpty();
        original.Arguments.ContainsKey("port").ShouldBeFalse();
        extended.ShouldNotBeSameAs(original);
        extended.Code.ShouldBe(original.Code);
    }

    [Fact]
    public void WithArgs_adds_several_arguments()
    {
        var error = new MyVpnError("code", "key").WithArgs(("a", "1"), ("b", "2"));

        error.Arguments["a"].ShouldBe("1");
        error.Arguments["b"].ShouldBe("2");
        error.Arguments.Count.ShouldBe(2);
    }

    [Fact]
    public void WithArg_chains_without_losing_existing_arguments()
    {
        var error = new MyVpnError("code", "key").WithArg("a", "1").WithArg("b", "2");

        error.Arguments.Count.ShouldBe(2);
        error.Arguments["a"].ShouldBe("1");
        error.Arguments["b"].ShouldBe("2");
    }

    [Fact]
    public void WithArg_overwrites_a_same_named_argument_in_the_copy_only()
    {
        var original = new MyVpnError("code", "key").WithArg("x", "old");
        var updated = original.WithArg("x", "new");

        updated.Arguments["x"].ShouldBe("new");
        original.Arguments["x"].ShouldBe("old");
    }

    [Fact]
    public void ToString_includes_the_code_and_message_key()
    {
        var error = new MyVpnError(ErrorCodes.ConfigInvalid, "error.settings.invalid");

        error.ToString().ShouldBe($"{ErrorCodes.ConfigInvalid} (error.settings.invalid)");
        error.ToString().ShouldContain(ErrorCodes.ConfigInvalid);
    }

    [Fact]
    public void ToString_appends_the_technical_detail_when_present()
    {
        var error = new MyVpnError(ErrorCodes.ConfigInvalid, "error.settings.invalid", ErrorSeverity.Error, "ctx");

        error.ToString().ShouldBe($"{ErrorCodes.ConfigInvalid} (error.settings.invalid): ctx");
    }

    [Fact]
    public void Equality_is_structural()
    {
        var first = new MyVpnError("code", "key");
        var second = new MyVpnError("code", "key");

        first.ShouldBe(second);
        first.GetHashCode().ShouldBe(second.GetHashCode());
        first.ShouldNotBe(second.WithArg("a", "1"));
    }

    [Fact]
    public void Arguments_is_never_null()
    {
        IReadOnlyDictionary<string, string>? args = null;
        var error = new MyVpnError("code", "key", Args: args);

        error.Arguments.ShouldNotBeNull();
        error.Arguments.ShouldBeEmpty();
    }

    [Fact]
    public void Error_codes_are_stable_strings()
    {
        ErrorCodes.ConfigInvalid.ShouldBe("config.invalid");
        ErrorCodes.XrayVersionProbeFailed.ShouldBe("xray.version_probe_failed");
        ErrorCodes.GeoAssetCorrupt.ShouldBe("geodata.corrupt");
        ErrorCodes.ShareLinkMalformed.ShouldBe("sharelink.malformed");
        ErrorCodes.SubscriptionHeaderInvalid.ShouldBe("subscription.header_invalid");
        ErrorCodes.OperationCancelled.ShouldBe("operation.cancelled");
    }
}
