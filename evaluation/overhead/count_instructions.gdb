set pagination off
set $count = 0
while $pc != 0
  stepi
  set $count++
end
printf "Result of function call: %d\n", $x0
printf "Number of executed instructions: %d\n", $count
