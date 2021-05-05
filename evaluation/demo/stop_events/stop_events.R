library(ggplot2)
library(dplyr)

data <- read.csv("aggregate.csv", colClasses = c("factor", "factor"))
x <- data %>%
  group_by(signal) %>%
  summarize(count = n())

plot <- ggplot(x, aes(x = signal, y = count)) +
  geom_bar(stat = "identity", fill = "gray") +
  scale_x_discrete(labels = 
                     c("Instr. breakpoint", "Segfault", "System call")
                   ) +
  labs(x = "Stop event type", y = "Number of events") +
  theme_minimal() +
  theme(text = element_text(size = 10),
        panel.grid.major.x = element_blank())

ggsave("stop_events.pdf", plot, width = 3.5, height = 1.75)

z <- data %>%
  subset(signal=="0x00857f") %>%
  group_by(label) %>%
  summarize(count = n())
z[order(-z$count),]
