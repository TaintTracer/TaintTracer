#include "TaintSource.h"

TaintSource::TaintSource(std::string label) : label_(std::move(label)) {

}

const char *TaintSource::get_name() const {
    return label_.c_str();
}
