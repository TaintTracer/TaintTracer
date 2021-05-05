library(ggplot2)
library(dplyr)

runs_dir <- "../../repackaging/"

orig_file = "test-results-2021-01-03-18-53-42/test_results.csv"
track_file = "test-results-2021-01-06-20-47-35/test_results.csv"

execve_filtered_runs <- read.csv(paste(runs_dir, track_file, sep = "")) %>%
  filter(Run.label == "tracing with taint tracking") %>%
  filter(execve == 0)
execve_filtered_run_labels <- execve_filtered_runs$Package.id

printf <- function(...) cat(sprintf(...))
genplot <- function(test_results_csv, run_label) {
  csv <- read.csv(test_results_csv)
  
  runs <- csv %>%
    filter(Run.label == run_label) %>%
    filter(Package.id %in% execve_filtered_run_labels) %>%
    mutate(activity_similarity = Reached.activities.intersection / Reached.activities.union) %>%
    arrange(activity_similarity) %>%
    mutate(x = 1:n())

  printf("Number of runs: %d\n", nrow(csv))
  printf("Number of runs (excluding execve): %d\n", nrow(runs))
  printf("Fraction of runs without tracer crashes: %f\n",
         nrow(filter(runs, Tracer.crashes == 0)) / nrow(runs))
  printf("Fraction of apps with contact permission: %f\n", 
         nrow(filter(runs, Has.contacts.permission == "true")) / nrow(runs))
  printf("Fraction of apps that access contact data out of the ones that have the permission: %f\n",
         nrow(filter(runs, Max.taint.size != 0)) / nrow(filter(runs, Has.contacts.permission == "true")))

  ggplot(data = runs, aes(x = x, y = activity_similarity, ymin = 0)) +
    scale_x_continuous(expand = c(0.02, 0)) +
    scale_y_continuous(expand = c(0, 0.01), labels = scales::percent) +
    labs(x = "Applications tested", y = "Activity similarity (%)") +
    geom_point(size = 0.4) +
    theme_minimal() +
    theme (text = element_text(size = 10))
}

orig <- genplot(paste(runs_dir, orig_file, sep = ""), "original2")
tracer <- genplot(paste(runs_dir, track_file, sep = ""), "tracing with taint tracking")

ggsave("activity_diff_orig.pdf", orig, width = 3.5, height = 2.5)
ggsave("activity_diff_tracer.pdf", tracer, width = 3.5, height = 2.5)
