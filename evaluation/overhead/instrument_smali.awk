/\.method javaOverheadBenchmarkIteration\(\)J/ {
  f = 1
}

match($0, /\.locals (.+)$/, m) {
  if (f) {
    ins_counter = "v" m[1];
    print "    .locals", m[1] + 1;
    print ""
    print "    const/4 " ins_counter ", 0x0"
    next
  }
}

/    [a-z].*/ {
  if (f) {
    print "    add-int/lit8 " ins_counter ", " ins_counter ", 0x1"
    print ""
  }
}

/    return.*/ {
  if (f) {
    print "    iput " ins_counter ", p0, Lorg/TaintTracer/TaintTracer/TestSourceSinkContextActivity;->iterationInstructions:I"
    print ""
  }
}

/\.end method/ {
  f = 0
}

/.*/ { print }
