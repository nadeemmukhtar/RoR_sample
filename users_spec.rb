# frozen_string_literal: true

require 'spec_helper'

describe ODLabTest do
  include PageObject::PageFactory
  include ODLabTest::Macros::UserMacro
  include ODLabTest::Macros::ReportMacro

  before(:context) do
    @user = Suite.instance.user
    @client = Suite.instance.client
    login(@user, @client)
  end

  after(:context) do
    user_logout
  end

  it 'should visit Layers report page' do
    visit_diagnostics_report('Layers')
  end

  it 'should visit Span of Control report page' do
    visit_diagnostics_report('Span of Control', false)
  end

  it 'should visit Managers report page' do
    visit_diagnostics_report('Managers')
  end

  it 'should visit Opportunity Overview report page' do
    visit_diagnostics_report('Opportunity Overview', false)
  end

  it 'should visit What if Archetype analysis report page' do
    visit_diagnostics_report("'What if' Archetype analysis")
  end

  it 'should visit Employee Hierarchy report page' do
    visit_diagnostics_report('Employee Hierarchy', false)
  end

  it 'should visit Baseline Analytics report page' do
    visit_diagnostics_report('Baseline Analytics')
  end

  it 'should visit Unfilled Roles report page' do
    visit_design_report('Unfilled Roles')
  end

  it 'should visit Duplicate Employees report page' do
    visit_design_report('Duplicate Employees')
  end

  it 'should visit Structure report page' do
    visit_design_report('Structure')
  end
end