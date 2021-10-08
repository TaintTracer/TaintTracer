library(data.table)
library(ggplot2)
library(dplyr)
library(zoo)

x <- fread('./TaintedMemoryOverTime.sh ../../log-copymydata-stacktrace.txt', sep = ",", header = FALSE, col.names = c("Time", "Bytes"))

x <- mutate(x, Time = as.POSIXct(paste("2020-", x$Time, sep=""), format = "%Y-%m-%d %H:%M:%OS")) %>%
     mutate(Time = as.numeric(as.POSIXct(Time),tz='UTC') * 1000) %>%
     mutate(Bytes = rollapply(Bytes, width = 2, FUN = max, align = 'right', partial = TRUE))

# Set time relative to first taint event
startTime <- x$Time[1]
x <- mutate(x, Time = Time - startTime) %>%
     mutate(event_id = row_number())

plot <- ggplot(x, aes(x = event_id, y = Bytes)) +
  geom_line() +
  labs(x = "Event number", y = "Bytes of tainted memory") +
  theme_minimal() +
  theme (text = element_text(size = 10))

ggsave("case_study_mem.pdf", plot, width = 3.5, height = 2.5)
