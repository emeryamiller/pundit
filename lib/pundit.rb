require "pundit/version"
require "pundit/policy_finder"
require "active_support/concern"
require "active_support/core_ext/string/inflections"
require "active_support/core_ext/object/blank"

module Pundit
  class NotAuthorizedError < StandardError
    attr_accessor :query, :record, :policy
  end

  class NotDefinedError < StandardError; end

  extend ActiveSupport::Concern

  class << self
    def policy_scope(user, scope, additional_attrs = nil)
      policy_scope = PolicyFinder.new(scope).scope
      args = [user, scope] + Array(additional_attrs)
      policy_scope.new(*args).resolve if policy_scope
    end

    def policy_scope!(user, scope, additional_attrs = nil)
      args = [user, scope] + Array(additional_attrs)
      PolicyFinder.new(scope).scope!.new(*args).resolve
    end

    def policy(user, record, additional_attrs = nil)
      policy = PolicyFinder.new(record).policy
      args = [user, record] + Array(additional_attrs)
      policy.new(*args) if policy
    end

    def policy!(user, record, additional_attrs = nil)
      args = [user, record] + Array(additional_attrs)
      PolicyFinder.new(record).policy!.new(*args)
    end
  end

  included do
    if respond_to?(:helper_method)
      helper_method :policy_scope
      helper_method :policy
      helper_method :pundit_user
    end
    if respond_to?(:hide_action)
      hide_action :policy_scope
      hide_action :policy_scope=
      hide_action :policy
      hide_action :policy=
      hide_action :authorize
      hide_action :verify_authorized
      hide_action :verify_policy_scoped
      hide_action :pundit_user
    end
  end

  def verify_authorized
    raise NotAuthorizedError unless @_policy_authorized
  end

  def verify_policy_scoped
    raise NotAuthorizedError unless @_policy_scoped
  end

  def authorize(record, query=nil)
    query ||= params[:action].to_s + "?"
    @_policy_authorized = true

    policy = policy(record)
    unless policy.public_send(query)
      error = NotAuthorizedError.new("not allowed to #{query} this #{record}")
      error.query, error.record, error.policy = query, record, policy

      raise error
    end

    true
  end

  def policy_scope(scope)
    @_policy_scoped = true
    @policy_scope or Pundit.policy_scope!(pundit_user, scope, pundit_additional_attributes)
  end
  attr_writer :policy_scope

  def policy(record)
    @policy or Pundit.policy!(pundit_user, record, pundit_additional_attributes)
  end
  attr_writer :policy

  def pundit_user
    current_user
  end

  def pundit_additional_attributes
    nil
  end
end
