library(ggplot2)
library(dplyr)
library(stringr)
library(scales)

x <- read.csv("results.csv") %>%
  rename(System = system, Environment = environment) %>%
  mutate(Environment = str_to_title(Environment)) %>%
  mutate(tainted.pct = tainted.registers/10 * 100) %>%
  select(-tainted.registers) %>%
  # Instructions executed in native benchmark: 2429
  # Instructions executed in java benchmark: 2378
  mutate(time = if_else(Environment == "Native", time/2429, time/2378)) %>%
  group_by(System, Environment, tainted.pct) %>%
  summarize_each(list(mean = mean, sd = sd))

plot <- ggplot(data=x, aes(
    x=tainted.pct,
    y=mean,
    shape=Environment,
    colour=System,
    interaction(System, Environment))) +
  geom_line() +
  geom_point() +
  scale_shape_manual(values=c(4, 19)) +
  scale_x_continuous(breaks = seq(0, 100, 10), minor_breaks = NULL) +
  scale_y_continuous(
    trans = log10_trans(),
    breaks = trans_breaks("log10", function(x) 10^x),
    labels = trans_format("log10", math_format(10^.x))) +
  geom_errorbar(aes(ymin = mean-sd, ymax = mean+sd), width = 1.5) +
  labs(x = "Instructions processing tainted data (%)", y = "Execution time per instruction (ns)") +
  theme_minimal() +
  theme(text = element_text(size = 10),
        # legend.justification = 'left',
        legend.position = 'bottom',
        legend.box = 'vertical',
        legend.box.just = 'left',
        legend.box.margin = margin(5,0,0,0),
        legend.margin = margin(-10, 0, 0, 0))

ggsave("overhead.pdf", plot, width = 3.5, height = 3.5)
plot

