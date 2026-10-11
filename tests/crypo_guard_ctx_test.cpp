#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>

#include <type_traits>
#include <utility>

using CryptoGuard::CryptoGuardCtx;

TEST(CryptoGuardCtx, IsMoveOnly) {
    static_assert(!std::is_copy_constructible_v<CryptoGuardCtx>);
    static_assert(!std::is_copy_assignable_v<CryptoGuardCtx>);
    static_assert(std::is_nothrow_move_constructible_v<CryptoGuardCtx>);
    static_assert(std::is_nothrow_move_assignable_v<CryptoGuardCtx>);
}

TEST(CryptoGuardCtx, SupportsMoveConstructionAndAssignment) {
    EXPECT_NO_THROW({
        CryptoGuardCtx original;
        CryptoGuardCtx moved{std::move(original)};
        CryptoGuardCtx assigned;
        assigned = std::move(moved);
    });
}
