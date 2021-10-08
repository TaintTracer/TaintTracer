# We attempt to make the Java benchmark similar to the native benchmark
# but the dex2oat optimizer optimized away the unused variables
.method newJavaOverheadBenchmark([III)V
    .locals 15

    # Load buffer into variables
    add-int/lit8 v10, p2, 0x0 # Move offset

    aget v0, p1, v10

    add-int/lit8 v10, v10, 0x1
    aget v1, p1, v10

    add-int/lit8 v10, v10, 0x1
    aget v2, p1, v10

    add-int/lit8 v10, v10, 0x1
    aget v3, p1, v10

    add-int/lit8 v10, v10, 0x1
    aget v4, p1, v10

    add-int/lit8 v10, v10, 0x1
    aget v5, p1, v10

    add-int/lit8 v10, v10, 0x1
    aget v6, p1, v10

    add-int/lit8 v10, v10, 0x1
    aget v7, p1, v10

    add-int/lit8 v10, v10, 0x1
    aget v8, p1, v10

    add-int/lit8 v10, v10, 0x1
    aget v9, p1, v10

    const/16 v11, 0x0 # Iteration counter
    move/from16 v12, p3 # Total iterations

    :goto_0
    if-ge v12, v11, :cleanup

    add-int/lit8 v0, v0, 0x1
    shr-int/lit8 v0, v0, 0x3

    add-int/lit8 v1, v0, 0x1
    shr-int/lit8 v1, v0, 0x3

    add-int/lit8 v2, v0, 0x1
    shr-int/lit8 v2, v0, 0x3

    add-int/lit8 v3, v0, 0x1
    shr-int/lit8 v3, v0, 0x3

    add-int/lit8 v4, v0, 0x1
    shr-int/lit8 v4, v0, 0x3

    add-int/lit8 v5, v0, 0x1
    shr-int/lit8 v5, v0, 0x3

    add-int/lit8 v6, v0, 0x1
    shr-int/lit8 v6, v0, 0x3

    add-int/lit8 v7, v0, 0x1
    shr-int/lit8 v7, v0, 0x3

    add-int/lit8 v8, v0, 0x1
    shr-int/lit8 v8, v0, 0x3

    add-int/lit8 v9, v0, 0x1
    shr-int/lit8 v9, v0, 0x3

    add-int/lit8 v11, v11, 0x1

    goto :goto_0

    :cleanup
    const/16 v0, 0x0
    const/16 v1, 0x0
    const/16 v2, 0x0
    const/16 v3, 0x0
    const/16 v4, 0x0
    const/16 v5, 0x0
    const/16 v6, 0x0
    const/16 v7, 0x0
    const/16 v8, 0x0
    const/16 v9, 0x0

    return-void
.end method
