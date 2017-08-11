# encoding: utf-8
# frozen_string_literal: true

module RubyScep
  module Version
    STRING = '0.1.0'

    module_function

    def version(*_args)
      STRING
    end
  end
end