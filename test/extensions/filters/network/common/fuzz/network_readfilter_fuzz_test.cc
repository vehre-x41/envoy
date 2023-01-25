#include "source/common/config/utility.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "test/config/utility.h"
#include "test/extensions/filters/network/common/fuzz/network_readfilter_fuzz.pb.validate.h"
#include "test/extensions/filters/network/common/fuzz/uber_readfilter.h"
#include "test/fuzz/fuzz_runner.h"
#include "test/test_common/test_runtime.h"
#include "src/libfuzzer/libfuzzer_mutator.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {

envoy::config::listener::v3::Filter
mutate_config(unsigned int seed, envoy::config::listener::v3::Filter* config = nullptr) {
  // TODO(jianwendong): After extending to cover all the filters, we can use
  // `Registry::FactoryRegistry<
  // Server::Configuration::NamedNetworkFilterConfigFactory>::registeredNames()`
  // to get all the filter names instead of calling `UberFilterFuzzer::filter_names()`.
  static const auto filter_names = UberFilterFuzzer::filterNames();
  static const auto factories = Registry::FactoryRegistry<
      Server::Configuration::NamedNetworkFilterConfigFactory>::factories();

  envoy::config::listener::v3::Filter result;
  if (config == nullptr) {
    config = &result;
  }
  // Choose a valid filter name.
  if (std::find(filter_names.begin(), filter_names.end(), config->name()) ==
      std::end(filter_names)) {
    absl::string_view filter_name = filter_names[seed % filter_names.size()];
    config->set_name(std::string(filter_name));
  }
  // Set the corresponding type_url for Any.
  auto& factory = factories.at(config->name());
  config->mutable_typed_config()->set_type_url(absl::StrCat(
      "type.googleapis.com/", factory->createEmptyConfigProto()->GetDescriptor()->full_name()));

  return *config;
}

DEFINE_PROTO_FUZZER(const test::extensions::filters::network::FilterFuzzTestCase& input) {
  //  TestDeprecatedV2Api _deprecated_v2_api;
  ABSL_ATTRIBUTE_UNUSED static PostProcessorRegistration reg = {
      [](test::extensions::filters::network::FilterFuzzTestCase* input, unsigned int seed) {
        // This post-processor mutation is applied only when libprotobuf-mutator
        // calls mutate on an input, and *not* during fuzz target execution.
        // Replaying a corpus through the fuzzer will not be affected by the
        // post-processor mutation.

        static unsigned config_mutation_cnt = 0;
        ENVOY_LOG_MISC(debug, "PostProc call for iteration #{}", config_mutation_cnt);
        // mutate the config part of the fuzzer only so often.
        static const unsigned config_mutation_limit = 10;
        static envoy::config::listener::v3::Filter config = mutate_config(seed);
        if (config_mutation_cnt > config_mutation_limit) {
          config = mutate_config(seed, &config);
          ENVOY_LOG_MISC(debug, "Mutating config: {}", config.DebugString());
          config_mutation_cnt = 0;
        }
        input->mutable_config()->operator=(config);

        unsigned cnt = 0;
        /* Mutate to find a valid configuration. */
        static protobuf_mutator::libfuzzer::Mutator mutator;
        static bool mutator_inited = false;
        if (!mutator_inited) {
          mutator.Seed(seed);
          mutator_inited = true;
        }
        for (;;) {
          try {
            MessageUtil::recursivePgvCheck(*input);
            break;
          } catch (const ProtoValidationException& e) {
            mutator.Mutate(input, 1l << 16);
            input->mutable_config()->set_name(config.name());
            input->mutable_config()->mutable_typed_config()->set_type_url(
                config.typed_config().type_url());
            ++cnt;
            ENVOY_LOG_MISC(debug, "Creating valid config, iteration {}, rejected because: {}", cnt,
                           e.what());
          }
        }

        ENVOY_LOG_MISC(debug, "Valid config after {} iterations: {}", cnt, input->DebugString());
        ++config_mutation_cnt;
      }};

  Envoy::Logger::Registry::setLogLevel(spdlog::level::trace);
  try {
    TestUtility::validate(input);
    // Check the filter's name in case some filters are not supported yet.
    static const auto filter_names = UberFilterFuzzer::filterNames();
    // TODO(jianwendong): remove this if block after covering all the filters.
    if (std::find(filter_names.begin(), filter_names.end(), input.config().name()) ==
        std::end(filter_names)) {
      ENVOY_LOG_MISC(debug, "Test case with unsupported filter type: {}", input.config().name());
      return;
    }
    static UberFilterFuzzer fuzzer;
    fuzzer.fuzz(input.config(), input.actions());
  } catch (const ProtoValidationException& e) {
    ENVOY_LOG_MISC(debug, "ProtoValidationException: {}", e.what());
  }
}

} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
