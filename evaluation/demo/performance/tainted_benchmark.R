library(tidyr)
library(Rmisc)
library(ggplot2)
x <- read.csv("tainted_benchmark.csv")
s <- summarySE(x, measurevar="Time", groupvar=c("System"))
plot <- ggplot(s, aes(x=System, y=Time)) + 
  geom_bar(position=position_dodge(), stat="identity", fill = "#aaaaaa") + 
  geom_errorbar(aes(ymin=Time-sd, ymax=Time+sd),
                width=.2,
                position=position_dodge(.9)) +
  
  theme_minimal() +
  theme(text = element_text(size = 10))

ggsave("tainted_benchmark.pdf", plot, width = 3.5, height = 1.75)
