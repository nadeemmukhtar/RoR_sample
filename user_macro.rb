# frozen_string_literal: true

module ODLabTest
  module Macros
    module UserMacro
      include RSpec::Matchers

      def login(user, client)
        visit(ODLabTest::Devise::Sessions::New).login(user, client)
        expect(on(ODLabTest::Layouts::TopMenu).client_name).to match(/#{client.name}/i)
      end

      def admin_logout
        on(ODLabTest::Layouts::LeftMenu).link_for('log out')
      end

      def user_logout
        on(ODLabTest::Layouts::LeftMenu).link_for('logout')
      end

      def create_user(user)
        visit_users_link
        visit_new_user_link
        on(ODLabTest::Admin::Users::New).create_user(user)
        expect(on(ODLabTest::Admin::Users::Index).user_names('__test__')).to include(/#{user.name}/i)
      end

      def confirmation_link(user)
        MailHelper.instance.password_reset_link(user.email)
      end

      def create_and_confirm_user(user)
        create_user(user)
        confirm_user(user)
      end

      def confirm_user(user)
        visit(ODLabTest::Passwords::Edit, using_params: { url: confirmation_link(user) }) do |page|
          expect_header('change my password')
          page.form(user)
        end
      end

      def delete_user(user)
        visit_users_link
        on(ODLabTest::Admin::Users::Index).link_for(user, 'delete')
        on(ODLabTest::Admin::Users::ConfirmDelete).delete_confirm
        expect(on(ODLabTest::Admin::Users::Index).user_names('__test__')).not_to include(/#{user.name}/i)
      end

      def delete_all_test_users
        visit_users_link
        on(ODLabTest::Admin::Users::Index).user_names('__test__').each do |name|
          visit(ODLabTest::Admin::Users::Index).link_for(OpenStruct.new(name: name), 'delete')
          on(ODLabTest::Admin::Users::ConfirmDelete).delete_confirm
          expect(on(ODLabTest::Admin::Users::Index).user_names('__test__')).not_to include(/#{name}/i)
        end
      end

      def visit_users_link
        on(ODLabTest::Layouts::LeftMenu).link_for('users')
        expect_header('users')
      end

      def visit_new_user_link
        on(ODLabTest::Admin::Users::Index).new_user
        expect_header('new user')
      end

      def expect_header(title)
        expect(on(ODLabTest::Layouts::Header).header).to match(/#{title}/i)
      end
    end
  end
end