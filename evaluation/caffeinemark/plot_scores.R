library(tidyr)
library(Rmisc) # Depends on plyr
library(ggplot2)
x <- read.csv("scores.csv")
# Convert data to long format
long <- gather(x, Type, Score, -System, factor_key = TRUE)
s <- summarySE(long, measurevar="Score", groupvar=c("System", "Type"))
plot <- ggplot(s, aes(x=Type, y=Score, fill=System)) + 
  geom_bar(position=position_dodge(), stat="identity") + 
  geom_errorbar(aes(ymin=Score-sd, ymax=Score+sd),
                width=.2,
                position=position_dodge(.9)) +
  scale_fill_grey(start = 0.4, end = 0.8) +
  theme_minimal() +
  theme(text = element_text(size = 10),
        legend.position = c(0.86, 0.83),
        legend.background = element_rect(fill="white", size=0.3))

ggsave("CaffeineMark.pdf", plot, width = 3.5, height = 3)
plot
