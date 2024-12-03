/*
This is a streamlined version of CLI11.hpp, stripping out the functionality not
used by this program.
*/

#pragma once
#include <functional>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>

// Forward declaration
class ParseError : public std::runtime_error {
public:
  ParseError(const std::string &msg) : std::runtime_error(msg) {}
};

class App {
private:
  class Option {
  public:
    std::string name;
    std::string description;
    std::string *value_ptr = nullptr;
    bool is_required = false;

    Option *required() {
      is_required = true;
      return this;
    }
  };

  class Subcommand {
  public:
    std::string name;
    std::string description;
    std::vector<std::string> aliases;
    std::function<void()> callback_fn;
    std::map<std::string, Option> options;
    std::map<std::string, Subcommand> subcommands;
    bool requires_subcommand = false;

    Subcommand() = default;

    Subcommand(const std::string &n, const std::string &desc)
        : name(n), description(desc) {}

    Subcommand *alias(const std::string &alias_name) {
      aliases.push_back(alias_name);
      return this;
    }

    Subcommand *callback(std::function<void()> cb) {
      callback_fn = std::move(cb);
      return this;
    }

    void require_subcommand() { requires_subcommand = true; }

    Option *add_option(const std::string &opt_name, std::string &value,
                       const std::string &opt_description) {
      auto &opt = options[opt_name];
      opt.name = opt_name;
      opt.description = opt_description;
      opt.value_ptr = &value;
      return &opt;
    }

    Subcommand *add_subcommand(const std::string &cmd_name,
                               const std::string &cmd_description) {
      auto &cmd = subcommands[cmd_name];
      cmd.name = cmd_name;
      cmd.description = cmd_description;
      return &cmd;
    }

    std::string help() const {
      std::ostringstream ss;
      ss << "Usage: " << name;

      // Show options in usage
      for (const auto &[opt_name, opt] : options) {
        ss << " ";
        if (opt.is_required) {
          ss << "<" << opt_name << ">";
        } else {
          ss << "[" << opt_name << "]";
        }
      }
      ss << "\n\n";

      if (!description.empty()) {
        ss << description << "\n\n";
      }

      // Show options detail
      if (!options.empty()) {
        ss << "Arguments:\n";
        for (const auto &[opt_name, opt] : options) {
          ss << "  " << opt_name;
          if (opt.is_required) {
            ss << " (required)";
          }
          if (!opt.description.empty()) {
            ss << ": " << opt.description;
          }
          ss << "\n";
        }
        ss << "\n";
      }

      // Show subcommands if any
      if (!subcommands.empty()) {
        ss << "Subcommands:\n";
        for (const auto &[name, cmd] : subcommands) {
          ss << "  " << name;
          if (!cmd.aliases.empty()) {
            ss << " (";
            for (size_t i = 0; i < cmd.aliases.size(); ++i) {
              if (i > 0)
                ss << ", ";
              ss << cmd.aliases[i];
            }
            ss << ")";
          }
          ss << ": " << cmd.description << "\n";
        }
      }

      return ss.str();
    }
  };

  std::string name;
  std::string description;
  std::string footer_text;
  std::map<std::string, Option> options;
  std::map<std::string, Subcommand> subcommands;
  bool fallthrough_flag = false;

public:
  App(const std::string &desc = "") : description(desc) {}

  Subcommand *add_subcommand(const std::string &name,
                             const std::string &description) {
    auto &cmd = subcommands[name];
    cmd.name = name;
    cmd.description = description;
    return &cmd;
  }

  App *fallthrough(bool value = true) {
    fallthrough_flag = value;
    return this;
  }

  void footer(const std::string &footer) { footer_text = footer; }

  Subcommand *get_subcommand(const std::string &name) {
    // Try direct name match
    auto it = subcommands.find(name);
    if (it != subcommands.end()) {
      return &it->second;
    }

    // Try aliases
    for (auto &[_, cmd] : subcommands) {
      if (std::find(cmd.aliases.begin(), cmd.aliases.end(), name) !=
          cmd.aliases.end()) {
        return &cmd;
      }
    }

    throw std::runtime_error("Subcommand not found");
  }

  void parse(const std::string &input) {
    std::vector<std::string> args;
    std::istringstream iss(input);
    std::string arg;
    while (iss >> arg) {
      args.push_back(arg);
    }

    if (args.empty())
      return;

    // Handle help flags
    if (args[0] == "-h" || args[0] == "--help") {
      std::cout << help() << std::endl;
      return;
    }

    Subcommand *cmd = nullptr;

    // Try direct name match
    auto it = subcommands.find(args[0]);
    if (it != subcommands.end()) {
      cmd = &it->second;
    } else {
      // Try aliases
      for (auto &[_, subcmd] : subcommands) {
        if (std::find(subcmd.aliases.begin(), subcmd.aliases.end(), args[0]) !=
            subcmd.aliases.end()) {
          cmd = &subcmd;
          break;
        }
      }
    }

    if (!cmd) {
      std::cout << "Unknown command: " << args[0] << "\n\n";
      std::cout << help() << std::endl;
      throw ParseError("Unknown command: " + args[0]);
    }

    // Remove the command name from args
    args.erase(args.begin());

    // Handle subcommand help
    if (!args.empty() && (args[0] == "-h" || args[0] == "--help")) {
      std::cout << cmd->help() << std::endl;
      return;
    }

    // Check if subcommand is required but missing
    if (cmd->requires_subcommand && (args.empty() || args[0][0] == '-')) {
      std::cout << "Error: Subcommand required\n\n";
      std::cout << cmd->help() << std::endl;
      throw ParseError("Subcommand required");
    }

    // If command has subcommands, try to parse them
    if (!cmd->subcommands.empty() && !args.empty()) {
      Subcommand *subcmd = nullptr;

      // Try direct name match for subcommand
      auto subit = cmd->subcommands.find(args[0]);
      if (subit != cmd->subcommands.end()) {
        subcmd = &subit->second;
      } else {
        // Try aliases for subcommand
        for (auto &[_, sub] : cmd->subcommands) {
          if (std::find(sub.aliases.begin(), sub.aliases.end(), args[0]) !=
              sub.aliases.end()) {
            subcmd = &sub;
            break;
          }
        }
      }

      if (!subcmd) {
        std::cout << "Unknown subcommand: " << args[0] << "\n\n";
        std::cout << cmd->help() << std::endl;
        throw ParseError("Unknown subcommand: " + args[0]);
      }

      // Remove the subcommand name from args
      args.erase(args.begin());

      // Check for required options in subcommand
      bool missing_required = false;
      for (const auto &[_, opt] : subcmd->options) {
        if (opt.is_required && args.empty()) {
          missing_required = true;
          break;
        }
      }

      if (missing_required) {
        std::cout << "Error: Missing required arguments\n\n";
        std::cout << subcmd->help() << std::endl;
        throw ParseError("Missing required arguments");
      }

      // Process subcommand options
      if (!args.empty() && !subcmd->options.empty()) {
        auto opt_it = subcmd->options.begin();
        for (const auto &arg : args) {
          if (opt_it != subcmd->options.end()) {
            if (opt_it->second.value_ptr) {
              *opt_it->second.value_ptr = arg;
            }
            ++opt_it;
          }
        }
      }

      if (subcmd->callback_fn) {
        subcmd->callback_fn();
      }
      return;
    }

    // Check for required options
    bool missing_required = false;
    for (const auto &[_, opt] : cmd->options) {
      if (opt.is_required && args.empty()) {
        missing_required = true;
        break;
      }
    }

    if (missing_required) {
      std::cout << "Error: Missing required arguments\n\n";
      std::cout << cmd->help() << std::endl;
      throw ParseError("Missing required arguments");
    }

    // If there are arguments, assign them to options in order
    if (!args.empty() && !cmd->options.empty()) {
      auto opt_it = cmd->options.begin();
      for (const auto &arg : args) {
        if (opt_it != cmd->options.end()) {
          if (opt_it->second.value_ptr) {
            *opt_it->second.value_ptr = arg;
          }
          ++opt_it;
        }
      }
    }

    if (cmd->callback_fn) {
      cmd->callback_fn();
    }
  }

  std::string help() const {
    std::ostringstream ss;
    ss << description << "\n\n";

    // Show options in usage
    for (const auto &[opt_name, opt] : options) {
      ss << " ";
      if (opt.is_required) {
        ss << "<" << opt_name << ">";
      } else {
        ss << "[" << opt_name << "]";
      }
    }
    ss << "\n\n";

    if (!description.empty()) {
      ss << description << "\n\n";
    }

    // Show options detail
    if (!options.empty()) {
      ss << "Arguments:\n";
      for (const auto &[opt_name, opt] : options) {
        ss << "  " << opt_name;
        if (opt.is_required) {
          ss << " (required)";
        }
        if (!opt.description.empty()) {
          ss << ": " << opt.description;
        }
        ss << "\n";
      }
      ss << "\n";
    }

    // Show commands
    if (!subcommands.empty()) {
      ss << "Commands:\n";
      for (const auto &[name, cmd] : subcommands) {
        ss << "  " << name;
        if (!cmd.aliases.empty()) {
          ss << " (";
          for (size_t i = 0; i < cmd.aliases.size(); ++i) {
            if (i > 0)
              ss << ", ";
            ss << cmd.aliases[i];
          }
          ss << ")";
        }
        ss << ": " << cmd.description << "\n";
      }
    }

    if (!footer_text.empty()) {
      ss << "\n" << footer_text << "\n";
    }

    return ss.str();
  }
};

namespace CLI {
using App = ::App;
using ParseError = ::ParseError;
} // namespace CLI

