#include "source/common/config/utility.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/network/well_known_names.h"

#include "test/config/utility.h"
#include "test/extensions/filters/network/common/fuzz/network_readfilter_fuzz.pb.validate.h"
#include "test/extensions/filters/network/common/fuzz/uber_readfilter.h"
#include "test/fuzz/fuzz_runner.h"
#include "test/test_common/test_runtime.h"
#include "src/libfuzzer/libfuzzer_mutator.h"

// for GenerateValidMessage-Visitor
#include "source/common/protobuf/visitor.h"
#include "validate/validate.h"

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

class GenerateValidMessage : public ProtobufMessage::ProtoVisitor, private pgv::BaseValidator {
public:
  class Mutator : public protobuf_mutator::libfuzzer::Mutator {
  public:
    using protobuf_mutator::libfuzzer::Mutator::Mutator;

    using protobuf_mutator::libfuzzer::Mutator::MutateString;
  };
  GenerateValidMessage(unsigned int seed) { mutator_.Seed(seed); }

  void onField(google::protobuf::Message& msg,
               const google::protobuf::FieldDescriptor& field) override {
    if (field.cpp_type() != Protobuf::FieldDescriptor::CPPTYPE_MESSAGE) {
      const google::protobuf::Reflection* reflection = msg.GetReflection();
      bool keepMutating = true;
      while (keepMutating) {
        try {
          switch (field.cpp_type()) {
          case Protobuf::FieldDescriptor::CPPTYPE_STRING: {
            std::string str = reflection->GetString(msg, &field);
            str = mutator_.MutateString(str, 1l << 16);
            reflection->SetString(&msg, &field, str);
            break;
          }
          default:
            keepMutating = false;
            break;
          }

          MessageUtil::recursivePgvCheck(msg);
          keepMutating = false;
        } catch (const ProtoValidationException&) {
          keepMutating = true;
        }
      }
    }
  }
  void onMessage(google::protobuf::Message&, absl::Span<const google::protobuf::Message* const>,
                 bool) override {}

private:
  Mutator mutator_;
};

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

        GenerateValidMessage generator(seed);
        ProtobufMessage::traverseMessage(generator, *input, true);

        ENVOY_LOG_MISC(debug, "Valid new config: {}", input->DebugString());
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
