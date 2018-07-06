# Class to define attributes and operations for User.
class User < ActiveRecord::Base

  require 'devise/models/database_authenticatable'
  require 'util/map_util'

  include Auth::Common
  include Auth::ForgotPassword
  include ::Invites

  # Added for xss security
  xss_terminate :except => [:cleartext_password]

  devise :database_authenticatable, :registerable, :omniauthable, :token_authenticatable,
         :recoverable, :rememberable, :trackable, :validatable, :remote_authenticatable

  attr_accessor :network, :network_name, :join_group, :sms_info, :group_choice, :from_import, :single_address, :skip_domain_validation
  attr_accessor :observer_arguments ###  hash attribute

  Fieldofstudy = ["All Subject Areas", "Early Childhood Education", "Elementary School", "Middle School", "English and Reading", "Fine Arts", "Foreign Languages", "Gifted Education", "Governor's Schools", "Health, Physical, and Driver Education", "History and Social Science", "Mathematics", "Science", "Special Education", "Career and Technical Education", "Other"]
  SUPER_LOGIN_USERS = ["maurice@regroup.com", "veena@regroup.com",
                       "bharadwaj.archak@tarento.com", "dalaric@regroup.com", "hlepik@regroup.com", "aandrades@regroup.com", "implementation@regroup.com",
                       "sjarvis@regroup.com", "oksana@regroup.com"]
  FTP_LOGIN_USERS = ["maurice@regroup.com", "hlepik@regroup.com", "oksana@regroup.com", "ralmanza@regroup.com"]

  CAMPUS_USER_CATEGORY = ["Parent", "Community"]

  define_model_callbacks :register, :activate

  # before_save :ensure_authentication_token
  # before_save :encrypt_password
  after_save :create_email_account, :if => Proc.new { |obj| (obj.new_record? || obj.email_changed? || obj.from_import) && !obj.email.blank? }
  before_create :make_activation_code, :set_newsletter
  # after_activate :verify_site_network, :confirm_primary_email
  validate :validates_with_block

  # Do not validate domains in test env
  if Rails.env.test?
    skip_domain_validation = true
  end

  before_validation do
    # set_login
    address = self.single_address || "#{street_address} #{city} #{state} #{zip}"
    if !address.blank? #&& !zip.blank?
      url = ["msuchouteau", "chouteaucounty911"].include?(self.primary_network.coded_name) ?
          "https://geograph.regroup.com/arcgis/rest/services/MSU/ChouteauStructures_CreateAdd1/GeocodeServer" : nil
      h = MapUtil::geocode(address, self.zip, url)
      self.lat, self.lng = h['y'], h['x'] if h

      # In case if user already enable the NOAA and later just update the address.
      if self.primary_network.noaa_alert? && self.user_profile && self.user_profile.enable_noaa? && !self.from_import
        begin
          Rails.logger.error "Getting counties based on #{self.lat} #{self.lng}"
          geocode = Geokit::Geocoders::FCCGeocoder.reverse_geocode("#{self.lat},#{self.lng}")
          self.user_profile.update_column(:noaa_fips, "0#{geocode.district_fips}")
        rescue => e
          Rails.logger.error "Unabe to get the county: #{e.inspect}"
        end
      end
      self.errors[:base] << "Invalid Address Format" if !h && self.single_address
    end
  end

  before_save do
    self.cleartext_password = password if (password && (cleartext_password != password))
    # set_login
  end

  def set_newsletter
    self.newsletter = 0
  end

  def validates_with_block
    if self.primary_network_id.blank? || !Network.where(:id => self.primary_network_id).first
      self.errors[:base] << "We didn't find that network.  Try selecting from the list"
    end
    if !skip_domain_validation && self.errors[:email].blank? && !self.email.blank?
      r = ValidateEmail.validate_mx_record(self.email)
      self.errors[:email] << "Email has an invalid format" unless r
    end
  end

  # validates :first_name, :allow_nil => :true, :format => { :with => /^[^0-9`<>!@#\$%\^&*+_=]+$/ }
  # validates :last_name, :allow_nil => :true, :format => { :with => /^[^0-9`<>!@#\$%\^&*+_=]+$/ }
  validates :primary_network_id, :presence => {:message => "Please choose a network from the list"}
  validates :carrier, :presence => {:message => 'Please select a carrier'}, :if => proc { |m| m.sms_info == true }
  validates :phone, :presence => {:message => 'Please enter a phone number'}, :if => proc { |m| m.sms_info == true }
  validates :phone, :allow_nil => :true, :if => proc { |m| !m.phone.blank? }, :format => {:with => /^(\d{10})$/}
  validates :phone, :uniqueness => true, :if => proc { |m| m.sms_info == true and !m.phone.nil? }
  # validates :network_login, :uniqueness => {:message => "login is already taken"}, :allow_nil => :true
  #validates :email, :presence => true, :email => true
  validates :email, :email => true, :allow_nil => true
  validates :email, :uniqueness => {:case_sensitive => false}, :allow_nil => true
  validates :email, :length => {:maximum => 160}, :allow_nil => true

  for context in [:default, :registration]
    validates :password, :length => {:minimum => 4}, :allow_nil => true, :on => context
    # validates :password_reset_key, :uniqueness => true, :if => Proc.new{ |m| !m.password_reset_key.nil? }, :on => context
    validates :reset_password_token, :uniqueness => true, :if => Proc.new { |m| !m.reset_password_token.nil? }, :on => context
    validates :password, :presence => true, :if => proc { |m| m.send :password_required? }, :on => context
  end

  # for context in [ :default, :registration, :ldap ]
  #   validates :email,:presence => true, :format => { :with => /^([^@\s]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})$/i }, :on => context #, :when => [ :default, :registration, :ldap ]
  #   # validates :phone, :allow_nil => :true, :if => proc{ |m| !m.phone.blank?}, :format => { :with => /^(\d{10})$/ }, :on => context #, :when => [ :default, :registration, :ldap ]
  # end

  has_many :email_accounts
  accepts_nested_attributes_for :email_accounts

  has_many :network_unsubscription
  has_many :user_logins
  has_many :user_networks
  has_many :networks, :through => :user_networks
  has_many :user_locations
  has_many :group_unsubscriptions
  has_many :user_groups
  has_many :groups, :through => :user_groups
  has_many :phone_numbers
  has_many :verified_user_networks, :class_name => 'UserNetwork', :conditions => ['verified = ?', true]
  has_many :unverified_user_networks, :class_name => 'UserNetwork', :conditions => ['verified = ?', false]
  has_many :self_admin_groups, :class_name => 'UserGroup', :conditions => ['administrator = ?', true]
  has_many :started_topics, :class_name => 'Topic', :foreign_key => :started_by_id
  has_many :modified_topics, :class_name => 'Topic', :foreign_key => :most_recent_editor_id
  has_many :comments
  has_many :files, :class_name => 'GroupFile' #, :accessor => :private  # only used for constraint management
  has_many :requests, :class_name => 'GroupMembershipRequest' #, :accessor => :private # only used for constraint management
  has_many :invites, :class_name => 'UserInvite', :foreign_key => :invited_by_id #, :accessor => :private #only used for constraint management
  has_many :history_edits, :class_name => 'TopicHistory' #, :accessor => :private # only used for constraint management
  has_many :aliases, :class_name => 'TopicAlias' #, :accessor => :private # only used for constraint management
  has_many :approvals, :class_name => 'GroupApprovalRequest' #, :accessor => :private #only used for constraint management
  # has_many :sms_statuses
  # has_many :voice_statuses
  has_one :user_image
  has_one :referred_by, :class_name => 'User', :foreign_key => :referred_by_id
  has_one :user_profile, :dependent => :destroy
  has_many :social_network_posts, :as => :source
  has_many :user_devices
  has_many :custom_field_values, :dependent => :destroy
  belongs_to :primary_network, :class_name => 'Network', :foreign_key => :primary_network_id
  has_many :administrative_user_groups, :class_name => 'UserGroup', :conditions => {:administrator => true, :can_authorize_users => true}
  has_many :map_infos

  enumerate :school_status do
    value :id => 1, :name => :prospective
    value :id => 2, :name => :undergraduate
    value :id => 3, :name => :graduate
    value :id => 4, :name => :faculty
    value :id => 5, :name => :alumni
    value :id => 6, :name => :none
  end

  enumerate :source do
    value :id => 1, :name => :web
    value :id => 2, :name => :mobile
    value :id => 3, :name => :migrated
    value :id => 4, :name => :quickreg
    value :id => 5, :name => :testing
    value :id => 6, :name => :topicreg
    value :id => 7, :name => :ldap
  end

  def email_required?
    false
  end

  def email_changed?
    !self.email.blank? ? super : false
  end

  def sms_statuses
    SmsStatus.where(:user_id => self.id) rescue []
  end

  def voice_statuses
    VoiceStatus.where(:user_id => self.id) rescue []
  end

  search_methods :name_contains, :campus_id_eq, :group_id_eq

  scope :name_contains, lambda { |query|
                        ADMIN_SPHINX_ENABLED ?
                            Search::SphinxSearchService.search(query, User, []) :
                            where("CONCAT_WS(' ', first_name, last_name) LIKE ?", "%#{query}%")
                      }
  scope :campus_id_eq, lambda { |campus_id| joins(user_networks: [:campuses]).where("campuses.id = ?", campus_id) }
  scope :group_id_eq, lambda { |group_id| joins(:groups).where("groups.id = ?", group_id) }

  def is_super_login_user?
    user_profile.super_login rescue false
  end

  def self.get_user_from_email email
    user = User.find_by_email(email) rescue nil
    user = EmailAccount.find_by_email(email).user rescue nil if user.nil?
    user
  end

  def set_encrypted_password
    if encrypted_password.blank? && cleartext_password.present?
      # password = cleartext_password
      # password_confirmation = cleartext_password
      update_attributes(:password => cleartext_password)
      # save
    end
  end

  def get_notification_groups session_network, params
    name_cond = nil

    #case1
    if params[:query] && params[:format].to_s.eql?("json")
      name_cond = ["groups.name like ?", "%" + params[:query].to_s.strip + "%"] unless params[:query].blank?
    end

    # case2
    if !params[:group_id].blank?
      name_cond = ["groups.id = ?", params[:group_id]]
    end

    #case 3
    if params[:starts_with]
      if params[:starts_with].to_s.eql?("0-9")
        name_cond = ["groups.name REGEXP '^[0-9]'"]
      else
        name_cond = ["groups.name like ?", params[:starts_with] + "%"]
      end
    end

    if session_network.present? && Network.current?(session_network, "usfca")
      UserGroup.fetch_user_groups({:user => self, :conditions => [name_cond, "groups.privacy in (1,2) or (groups.privacy = 3 && #{is_network_admin?(primary_network).present?})", "groups.coded_name != 'newsletter-regroup-updates'"], :select => "user_groups.*", :object => UserGroup, :order => "groups.name asc"})
    else
      UserGroup.fetch_user_groups({:user => self, :conditions => [name_cond, "groups.coded_name != 'newsletter-regroup-updates'"], :select => "user_groups.*", :object => UserGroup, :order => "groups.name asc"})
    end
  end

  # Method to create email account for the user.
  def create_email_account
    email_account = EmailAccount.find_or_initialize_by_user_id_and_email(id, email)
    email_account.skip_domain_validation = self.skip_domain_validation

    ea = self.email_accounts.where(["email != ?", email]).where(:primary => true).first
    ea.update_column(:primary, false) if ea
    ea.update_column(:edited_at, Time.now) if ea && !from_import

    email_account.primary = true
    email_account.edited_at = Time.now unless from_import
    email_account.confirmed = true if from_import == true
    email_account.receive_email = email_account.confirmed
    email_account.source = :csv if ((from_import == true) && ["utexas", "utbeta", "demo", "bcc", "wvstateu", "kpu", "du"].include?(self.primary_network.coded_name))
    if email_account.new_record? || email_account.changed?
      email_account.save
    else
      email_account.touch
    end
  end

  # Method to create primary network relationship
  # and make him join site network
  def create_user_network
    self.user_networks.build(:network_id => self.primary_network_id, :primary => true).save unless UserNetwork.where(:network_id => self.primary_network_id, :user_id => self.id).first

    n = Network.where(:coded_name => 'site', :type => :site).first
    if n
      self.user_networks.build(:network_id => n.id).save unless UserNetwork.where(:network_id => n.id, :user_id => self.id).first
    end
  end

  # # Method to get full name of the user
  #   def get_full_name
  #     last_name ? (first_name + " " + last_name) : first_name
  #   end

  # Method to get full name of the user with last name first
  def get_full_name
    [first_name, last_name].select(&:present?).join(' ')
  end

  alias_method :full_name, :get_full_name

  def is_group_admin?(group)
    is_network_admin?(group.network) || !!self.user_groups.administrators.where(:group_id => group.id).first
  end

  def is_member_of_multiple_groups?
    user_groups.size > 1
  end

  def is_member?(network_id)
    UserNetwork.where(:network_id => network_id, :user_id => self.id).first
  end

  def make_activation_code
    self.activation_code = self.class.make_key
  end

  def verify_site_network
    site_network = self.unverified_user_networks.find_all { |un| un.network.email_domains.blank? }
    site_network.each do |un|
      un.verified = true
      un.save
    end
  end

  def confirm_primary_email
    # only confirm if we're activated
    if self.activated?
      account = self.email_accounts.where(:email => self.email).first
      account.confirm if account
    end
  end

  def primary_email
    self.email_accounts.where(:primary => true).first.email rescue ""
  end

  def secondary_emails
    self.email_accounts.where(:primary => false).collect(&:email).uniq.join(', ')
  end

  # Method to check if a user's account is connected to facebook.
  def connected_to_facebook?
    !self.facebook_id.blank?
  end

  def is_network_admin?(network)
    return UserNetwork.where(:network_id => network.id, :user_id => self.id, :administrator => true).first if network
    false
  end

  def is_group_or_network_admin?(user)
    if is_network_admin?(user.primary_network)
      return true
    elsif !user.primary_network.restrict_access
      return UserGroup.where(:group_id => user.groups.collect(&:id), :user_id => self.id, :administrator => true).first
    end
    false
  end

  def is_network_or_group_admin_of_any?
    UserNetwork.where(:user_id => self.id, :administrator => true).first || UserGroup.where(:user_id => self.id, :administrator => true, :can_post => true, :can_approve_topics => true, :can_approve_members => true, :can_edit_group => true, :can_manage_users => true, :can_authorize_users => true).first
  end

  def unsubscribe_for?(group_id)
    GroupUnsubscription.where(:user_id => self.id, :group_id => group_id).first
  end

  def roles(nw)
    un = user_networks.where(:network_id => nw.id).first
    return OpenStruct.new({:network_admin => false, :location_admin => false, :group_admin => false, :normal_user => false, :only_network_admin => false, :only_location_admin => false, :only_group_admin => false, :is_admin => false}) if un.blank?

    location_admin = nw.enable_campus && un.campuses_user_networks.where(:administrator => true).first ? true : false
    group_admin = user_groups.joins(:group).where(:user_groups => {:administrator => true}, :groups => {:network_id => nw.id}).first ? true : false
    normal_user = (un.administrator || location_admin || group_admin) ? false : true

    is_admin = un.administrator || location_admin || group_admin
    only_network_admin = un.administrator && !location_admin && !group_admin
    only_location_admin = !un.administrator && location_admin && !group_admin
    only_group_admin = !un.administrator && !location_admin && group_admin

    OpenStruct.new({:network_admin => un.administrator, :location_admin => location_admin, :group_admin => group_admin, :normal_user => normal_user, :only_network_admin => only_network_admin, :only_location_admin => only_location_admin, :only_group_admin => only_group_admin, :is_admin => is_admin})
  end

  ##
  # Method to check if the user is an admin of the network.
  #
  # Accpeted parameters :
  # :: * *network*
  #
  # If network id is present it verifies if a user is admin for this network, else
  # checks for the user's primary network.
  def is_admin?(network_id=nil)
    network_id ||= primary_network_id
    network = Network.where(:id => network_id).first
    roles(network).is_admin ? true : nil
  end

  def is_authorize_sender?(nid=nil)
    nid ||= self.primary_network_id
    return !self.user_groups.joins(:group).where(:groups => {:network_id => nid}, :administrator => true, :can_post => true).empty?
  end

  def get_posting_group_ids(nid=nil)
    nid ||= self.primary_network_id
    return self.user_groups.joins(:group).where(:groups => {:network_id => nid}, :administrator => true, :can_post => true).pluck(:group_id)
  end

  def get_postable_groups
    if self.is_admin_network_id?(self.primary_network_id)
      UserGroup.fetch_user_groups({:conditions => [{:network_id => self.primary_network_id}], :order => "groups.name asc"})
    else
      UserGroup.fetch_user_groups({:user => self, :conditions => ["user_groups.administrator = 1 and user_groups.can_post =1", {:network_id => self.primary_network_id}], :order => "groups.name asc"})
    end
  end

  def make_authorize_sender(g)
    ug = UserGroup.where(:user_id => self.id, :group_id => g.id).first
    if ug
      ug.update_attributes({:administrator => true, :can_post => true,
                            :can_approve_topics => false, :can_approve_members => false,
                            :can_edit_group => false, :can_manage_users => false, :can_authorize_users => false
                           })
    else
      UserGroup.create(:user_id => self.id, :group_id => g.id, :administrator => true,
                       :can_post => true, :can_approve_topics => false, :can_approve_members => false,
                       :can_edit_group => false, :can_manage_users => false, :can_authorize_users => false
      )
    end
    return true
  end

  def make_group_limited_admin(g)
    ug = UserGroup.where(:user_id => self.id, :group_id => g.id).first
    if ug
      ug.update_attributes({:administrator => true, :can_post => true,
                            :can_approve_topics => true, :can_approve_members => true,
                            :can_edit_group => false, :can_manage_users => false, :can_authorize_users => true
                           })
    else
      UserGroup.create(:user_id => self.id, :group_id => g.id, :administrator => true,
                       :can_post => true, :can_approve_topics => true, :can_approve_members => true,
                       :can_edit_group => false, :can_manage_users => false, :can_authorize_users => true
      )
    end
    return true
  end

  def make_group_user(g)
    ug = UserGroup.where(:user_id => self.id, :group_id => g.id).first
    if ug
      ug.update_attributes({:administrator => false, :can_post => false,
                            :can_approve_topics => false, :can_approve_members => false,
                            :can_edit_group => false, :can_manage_users => false, :can_authorize_users => false
                           })
    else
      UserGroup.create(:user_id => self.id, :group_id => g.id, :administrator => false,
                       :can_post => false, :can_approve_topics => false, :can_approve_members => false,
                       :can_edit_group => false, :can_manage_users => false, :can_authorize_users => false
      )
    end
    return true
  end


  def make_group_admin(g)
    ug = UserGroup.where(:user_id => self.id, :group_id => g.id).first
    if ug
      ug.update_attributes({:administrator => true, :can_post => true,
                            :can_approve_topics => true, :can_approve_members => true,
                            :can_edit_group => true, :can_manage_users => true, :can_authorize_users => true
                           })
    else
      UserGroup.create(:user_id => self.id, :group_id => g.id, :administrator => true,
                       :can_post => true, :can_approve_topics => true, :can_approve_members => true,
                       :can_edit_group => true, :can_manage_users => true, :can_authorize_users => true
      )
    end
    return true
  end

  def show_networks_and_create_group?(network=nil)
    return (self.is_network_admin?(self.primary_network) || !UserGroup.where(:user_id => self.id, :administrator => true, :can_manage_users => true, :can_edit_group => true).blank? || (self.primary_network.enable_campus && !self.get_network_campus_admin_cumpuses(self.primary_network).blank?))
  end

  # Method to retreive the sms number of the user.
  def get_sms_number
    self.phone_numbers.where(["type in(1, 3)"]).first
  end

  def ldap_user?
    return self.source.eql?(:ldap)
  end

  def can_use_ipaws?(network)
    return network && network.enable_ipaws? && !self.user_networks.where("network_id = ? AND (administrator = ? OR ipaws = ?)", network.id, true, true).empty?
  end

  # Method to retreive the voice number of the user.
  def get_voice_number
    self.phone_numbers.where(["type in(2, 3)"]).first
  end

  # def update_with_password(params={})
  #   current_password = params.delete(:current_password) if !params[:current_password].blank?

  #   params.delete(:password) if params[:password].blank?
  #   params.delete(:password_confirmation) if params[:password_confirmation].blank?

  #   result = if valid_password?(current_password)
  #     update_attributes(params)
  #   else
  #     self.errors.add(:current_password, current_password.blank? ? :blank : :invalid)
  #     self.attributes = params
  #     false
  #   end

  #   clean_up_passwords
  #   result
  # end

  def get_primary_caller_id
    primary_network.caller_id rescue ""
  end

  # Method to find user's login
  def get_user_login
    #self.network_login.blank? ? self.login : self.network_login.split('-',2)[1]
    self.get_network_login.blank? ? "" : self.get_network_login.gsub(self.primary_network.coded_name+'-', '') rescue ''
  end

  def get_network_login
    user_logins.where("network_login like ?", "#{primary_network.coded_name}%").first.network_login rescue nil
  end

  def get_user_logins
    user_logins.where("network_login like ?", "#{primary_network.coded_name}%").pluck('network_login').join(";")
  end

  def have_multiple_logins?
    user_logins.size > 1
  end

  def get_network_of_db_id
    if !external_db_id.blank?
      self.networks.detect { |n| external_db_id.start_with?(n.coded_name + "-") }
    end
  end

  def get_all_network_logins viewing_user
    if viewing_user.eql?(self)
      all_networks = networks
    else
      all_networks = [viewing_user.primary_network]
    end
    if true #have_multiple_logins?
      arr = []
      user_logins.pluck(:network_login).each do |l|
        all_networks.each do |n|
          if l.index(n.coded_name.to_s + '-')
            str = l.gsub("#{n.coded_name}-", "")
            str += " (#{n.coded_name}"
            # str += " - primary network" if n.coded_name == primary_network.coded_name
            str += ")"
            arr << str
            break
          end
        end
      end
      return arr.join(', ')
    else
      return get_user_login
    end
  end

  def get_all_network_login_hash viewing_user
    hash = Hash.new
    if viewing_user.eql?(self)
      all_networks = networks
    else
      all_networks = [viewing_user.primary_network]
    end
    if true #have_multiple_logins?
      arr = []
      user_logins.each do |log|
        l = log.network_login
        all_networks.each do |n|
          if l.index(n.coded_name.to_s + '-')
            str = l.gsub("#{n.coded_name}-", "")
            hash[log.id] = [n.coded_name, str]
            break
          end
        end
      end
    else
      hash[user_logins.first.id] = [user_logins.first.network_login.gsub("-"+get_user_login, ''), get_user_login] if user_logins.first
    end
    return hash
  end

  # Method to check if the user is an admin of the given network.
  #
  # Accpeted parameters :
  #
  # :: * *network*
  def is_admin_network_id?(network)
    return UserNetwork.where(:network_id => network, :user_id => self.id, :administrator => true).first if network
    false
  end

  # Method to save user to the database based on the *context* passed.
  def register(context = :registration)
    x = save(:context => context)
    run_callbacks(:register) { notify_observers :after_register }
    p self.errors unless x
    x
  end

  # Method to save user to the database in context of :ldap
  def ldap_register
    x = save(:context => :ldap)
    p self.errors unless x
    x
  end

  ## start for Facebook

  # Method to publish the message on facebook profile
  #
  # Parameters :
  #
  #:: * *msg*
  #:: * *link_txt*
  #:: * *link*
  #
  # Checks if a user has authenticated to FB and post on the wall, else raise an error.
  def publish_on_fb_profile(msg, link_txt, link)
    if self.facebook_id
      begin
        @graph = Koala::Facebook::API.new(fb_access_token)
        if link && link_txt
          @graph.put_wall_post(msg, {:actions => [{:name => link_txt, :link => link}].to_json})
        else
          @graph.put_wall_post(msg)
        end
      rescue => e
        ::Rails.logger.error("Opp! got error while publishing to user's facebook profile : #{e.inspect}")
      end
    end
  end

  # Method to publish the message on facebook page
  #
  # Parameters :
  #
  #:: * *msg*
  #:: * *link_txt*
  #:: * *link*
  #
  # Checks if a user has authenticated to FB and post on the wall, else raise the error.
  def publish_on_fb_page(msg, link_txt, link)
    if facebook_id && facebook_page_id
      begin
        u = Koala::Facebook::API.new(self.fb_access_token)
        page_token = Koala::Facebook::API.new(self.fb_access_token).get_page_access_token(self.facebook_page_id) #['access_token']
        @graph = Koala::Facebook::API.new(page_token)
        if link && link_txt
          @graph.put_wall_post(msg, {:actions => [{:name => link_txt, :link => link}].to_json})
        else
          @graph.put_wall_post(msg)
        end
      rescue => e
        ::Rails.logger.error("Opp! got error while spublishing to user's facebook page : #{e.inspect}")
      end
    end
  end

  # Method to get the facebook user object from the access token received.
  #
  # Parameters :
  #
  #:: * *facebook_id*
  def get_facebook_user(facebook_id)
    @graph = Koala::Facebook::API.new(fb_access_token) if !fb_access_token.blank?
    @graph ? @graph.get_object("me") : nil
  end

  # Method to get the facebook page object from the access token received.
  #
  # Parameters :
  #
  #:: * *page_id*
  #
  # Returns : Facebook page object
  def get_facebook_page(page_id)
    # Facebooker::Page.new(page_id)
    @graph = Koala::Facebook::API.new(fb_access_token)
    page_token = @graph.get_page_access_token(page_id)
    @page_graph = Koala::Facebook::API.new(page_token)
    @page_graph.get_object('me')
  end

  # Method to get the facebook post permissions from the access token received.
  def get_fb_permissions
    if fb_access_token
      @graph = Koala::Facebook::API.new(fb_access_token)
      @graph.get_connections('me', 'permissions') rescue []
    else
      []
    end
  end

  # Method to check if the user has provided publish permissions on facebook profile.
  def has_fb_permission
    get_fb_permissions.detect { |e| "publish_actions" == e["permission"] } ? true : false
  end

  # Method to check if the user has provided publish permissions on facebook page.
  def has_fb_page_permission
    get_fb_permissions.detect { |e| "manage_pages" == e["permission"] } ? true : false
  end

  def attach_facebook_friends(facebook_cookies)
    # add facebook friends info
    graph = Koala::Facebook::API.new(facebook_cookies['access_token'])
    graph.get_connections("me", "friends").each do |fb_friend|
      FacebookFriend.create(:collegewikis_id => self.id, :facebook_id => facebook_cookies['user_id'], :facebook_friend_id => fb_friend['id'], :connected => 0)
    end
  end

  def has_map_mode_enabled?
    primary_network.map_mode rescue false
  end

  ## custom Devise mailer layout
  def send_reset_password_instructions()
    generate_reset_password_token! if should_generate_reset_token?
    send_devise_notification(:reset_password_instructions)
  end

  def send_sms_reset_password_instructions(phone, country_code)
    tmp_pwd = SecureRandom.urlsafe_base64(5)
    self.password = tmp_pwd
    self.password_confirmation = tmp_pwd
    self.save
    message = "Your request for temporary password from #{self.primary_network.name} : #{tmp_pwd}"
    Cdyne::send_test_sms(["#{country_code}#{phone}"], message)
    self
  end

  attr_accessor :url_scheme, :host, :phone

  def self.send_reset_password_instructions(attributes={})
    recoverable = find_or_initialize_with_errors(reset_password_keys, attributes, :not_found)
    recoverable.url_scheme = attributes[:url_scheme]
    recoverable.host = attributes[:host]
    recoverable.send_reset_password_instructions() if recoverable.persisted?
    recoverable
  end

  def self.send_sms_reset_password_instructions(attributes={})
    recoverable = find_or_initialize_with_errors(reset_password_keys, attributes, :not_found)
    recoverable.phone = attributes[:phone]
    recoverable.send_sms_reset_password_instructions() if recoverable.persisted?
    recoverable
  end

  ## end for FB

  def full_address
    ActiveSupport::Deprecation.warn('Full address information for user replaced to User -> UserLocation -> UserAddress model')
    "#{street_address} #{city} #{state} #{zip}"
  end

  # Method to check if user's profile is marked as private
  def has_private_profile?
    self.private
  end

  # Method to check if current user is a network admin for any of the networks a user belong to
  def is_network_admin_for_user? user
    UserNetwork.where(:network_id => user.networks.collect(&:id), :user_id => self.id, :administrator => true).size > 0
  end

  # Method to check if current user is a group admin for any group of the networks a user belong to
  def is_group_admin_for_network? network
    user_groups.joins(:group).where(:groups => {:network_id => network.id}, :administrator => true, :can_authorize_users => true).size > 0
  end

  # Method to check if current user is a group admin for any of the groups a user belong to
  def is_group_admin_for_user? user
    !primary_network.restrict_access && UserGroup.where(:group_id => user.groups.collect(&:id), :user_id => self.id, :administrator => true).size > 0
  end

  # Method to check if current user is a admin of the current_campus
  def is_location_admin_for_user? user
    viewing_user_campuses = user.my_campuses.pluck("campuses.id")
    admin_campuses = self.my_campuses(nil, true).pluck("campuses.id")
    return admin_campuses.any? { |c| viewing_user_campuses.include?(c) }
  end

  # Method to check if current user is any kind of admin (network, location or group ) of the current_network
  def is_any_admin?(network)
    user_roles = self.roles(network)
    return user_roles.network_admin || user_roles.location_admin || user_roles.group_admin
    false
  end

  def my_campuses(nid=nil, admin=nil)
    cond = ["user_networks.user_id = #{self.id} and networks.enable_campus = true"]
    cond << "campuses_user_networks.administrator=#{admin}" if admin != nil
    cond << "networks.id in (#{nid.to_a.join(",")})" if !nid.blank?
    Campus.joins({:campuses_user_networks => {:user_network => :network}}).where(cond.join(" and "))
  end

  # get network_admin or location admin locations
  def get_locations(network)
    user_roles = self.roles(network)
    if network.is_admin?(self)
      return network.campuses
    elsif user_roles.location_admin
      return self.my_campuses(network.id.to_s, true)
    end
  end


  # Method to check if users profile is accessible
  def has_profile_access? user, read_only = false
    # Checks
    # 1. If same user is accessing the profile => Allow
    # 2. If a network admin is accessing the profile => Allow
    # 3. If a group admin is accessing the profile and the profile is not private => Allow
    # 4. Otherwise => Don't allow

    return self.id.eql?(user.id) || self.is_network_admin_for_user?(user) || (self.is_group_admin_for_user?(user) && !user.has_private_profile?) || self.is_location_admin_for_user?(user)
  end


  def belongs_to_static_group? network_id
    user_groups.joins(:group).where(:groups => {:static => true, :network_id => network_id}).size > 0
  end

  def belongs_to_multiple_network?
    user_networks.size > 1
  end

  def set_regroup_updates
    self.newsletter ? self.add_to_newsletter_group : self.remove_from_newsletter_group
  end

  def add_to_newsletter_group
    group = Group.add_newsletter_group
    self.make_group_user(group)
  end

  def remove_from_newsletter_group
    begin
      network = Network.where(:coded_name => "regroup_updates").first
      group = Group.where(:coded_name => "newsletter-regroup-updates", :network_id => network.id).first
      user_group = UserGroup.where(:user_id => self.id, :group_id => group.id).first
      user_group.destroy if user_group.present?
      user_network = UserNetwork.where(:network_id => network.id, :user_id => self.id).first
      if user_network.present? && !self.is_network_admin?(network).present?
        user_network.destroy
      end
    rescue => e
      ::Rails.logger.error e
    end
  end

  def add_to_network(network_id, context = :default)
    un = self.user_networks.build(:network_id => network_id, :verified => true)
    un.save(:context => context)
    un
  end

  def add_custom_field_values(custom_fields)
    if custom_fields.present? && self.primary_network.custom_fields.present?
      self.primary_network.custom_fields.each do |cf|
        cfv = cf.value_for(self)
        if cfv.present?
          if custom_fields["#{cf.key}"].present?
            cfv.update_attribute(:value, custom_fields["#{cf.key}"])
          else
            cfv.destroy
          end
        else
          CustomFieldValue.create!(:custom_field_id => cf.id, :user_id => self.id, :value => custom_fields["#{cf.key}"]) if custom_fields["#{cf.key}"].present?
        end
      end
    end
  end

  def purgeable?
    user_networks.joins(:network).where("networks.coded_name != 'regroup_updates'").size == 1 rescue false
  end

  def get_custome_fields
    if primary_network.custom_fields.present?
      fields = ""
      primary_network.custom_fields.each do |cf|
        fields += "#{cf.key}|"
        fields += "#{cf.value_for(self).value}" if cf.value_for(self)
        fields += ";"
      end
      fields
    end
  end

  def get_campuses(n = nil)
    cond = n ? {:id => n.id, :enable_campus => true} : {:enable_campus => true}
    user_networks.joins(:network).where(:networks => cond).collect { |un| un.campuses }.flatten
  end

  # Check for multiple address
  def get_address(id)
    UserAddress.includes(user_location: :user).where(users: {:id => id}, user_locations: {:type => "1"})
  end


  def map_campuses(viewing_user)
    viewing_user_network_ids = viewing_user.user_networks.where(:administrator => true).pluck(:network_id)
    if viewing_user_network_ids.blank?
      [[], []]
    else
      usr_ntws = user_networks.joins(:network).where(:networks => {:enable_campus => true}, :network_id => viewing_user_network_ids)
      [Campus.where(:network_id => usr_ntws.pluck(:network_id)), usr_ntws.pluck("user_networks.id")]
    end
  end

  def get_all_campus_names
    user_networks.inject({}) { |acc, v|
      campuses = v.campuses.collect(&:name).join(",")
      acc[v.network.coded_name] = campuses if !campuses.blank?
      acc
    }
  end

  def get_network_campus_admin_cumpuses(nid)
    user_networks.joins(:network).where(:networks => {:id => nid, :enable_campus => true}).first.campuses.where(:campuses_user_networks => {:administrator => true}) rescue []
  end

  def get_all_campus_admin_campuses_groups(nid)
    campuses = self.get_network_campus_admin_cumpuses(nid)
    campus_ids = campuses.pluck("campuses.id") << 0
    normal_and_location_admin_cond = "(campuses_groups.campus_id in (#{campus_ids.join(",")})) or (user_groups.user_id=#{self.id} and user_groups.administrator = 1 and user_groups.can_post =1)"
    UserGroup.fetch_user_groups({:joins => [:campuses_groups, :user_groups], :conditions => [normal_and_location_admin_cond, {:network_id => nid}], :order => "groups.name asc"})
  end

  def get_group_admin_group_ids(nid)
    return self.user_groups.joins(:group).where(:groups => {:network_id => nid}, :administrator => true).pluck(:group_id)
  end

  def get_all_topics_of_network(network, query="")
    query ||= ""
    user_roles = roles(network)
    if user_roles.network_admin
      topics = network.topics.include_data.report_topics(Time.now, query)
    elsif user_roles.location_admin
      group_ids = self.get_all_campus_admin_campuses_groups(network.id).pluck("groups.id") + self.get_group_admin_group_ids(network.id)
      topics = Topic.group_by_topics(group_ids.uniq).include_data.report_topics(Time.now, query)
    elsif user_roles.group_admin
      group_ids = self.get_group_admin_group_ids(network.id)
      topics = Topic.group_by_topics(group_ids.uniq).include_data.report_topics(Time.now, query)
    end
    return topics
  end

  def get_all_voice_polls_of_network(network, ivr_type)
    user_roles = roles(network)
    source = IvrQuestion::Source.flag_map.keys
    if user_roles.network_admin
      group_ids = network.groups.map(&:id)
    elsif user_roles.location_admin
      group_ids = self.get_all_campus_admin_campuses_groups(network.id).pluck("groups.id") + self.get_group_admin_group_ids(network.id)
    elsif user_roles.group_admin
      group_ids = self.get_group_admin_group_ids(network.id)
    end
    IvrQuestion.group_polls(group_ids).sent_polls(source, ivr_type).order("created_at desc")
  end

  def get_summary_topics_of_network(network, data_for)
    user_roles = roles(network)
    if user_roles.network_admin
      group_ids = UserGroup.fetch_user_groups({:conditions => [{:network_id => network.id}]}).pluck("groups.id")
    elsif user_roles.location_admin
      group_ids = self.get_all_campus_admin_campuses_groups(network.id).pluck("groups.id")
    elsif user_roles.group_admin
      group_ids = UserGroup.fetch_user_groups({:user => self, :conditions => ["user_groups.administrator = 1 and user_groups.can_post =1", {:network_id => network.id}]}).pluck("groups.id")
    end
    if ["1 Month", "3 Months", "12 Months"].include?(data_for)
      months, format = data_for.eql?("12 Months") ? [11, "b"] : [2, "M"]
      query = data_for.eql?("1 Month") ? "created_at >= '#{30.days.ago.beginning_of_day}'" : "created_at >= '#{months.month.ago.beginning_of_month}'"
      if user_roles.network_admin
        topics = network.topics.include_data.report_topics(Time.now, nil).where(query)
      elsif user_roles.location_admin || user_roles.group_admin
        topics = Topic.group_by_topics(group_ids.uniq).include_data.report_topics(Time.now, nil).where(query)
      end
    elsif ["Last Post", "SP Pie"].include?(data_for)
      if user_roles.network_admin
        topic = network.topics.include_data.report_topics(Time.now, nil).first
        topics = topic.get_related_topics.unshift(topic) rescue []
      elsif user_roles.location_admin || user_roles.group_admin
        topic = Topic.group_by_topics(group_ids.uniq).include_data.report_topics(Time.now, nil).first
        topics = topic.get_related_topics.unshift(topic) rescue []
        topics = topics.select { |topic| group_ids.include?(topic.group_id) } if topics && !topics.empty?
      end

    else
      topics = []
    end
    return topics
  end

  def find_group_categories(nw)
    categories = Group::Category.flag_map
    cfs = CustomField.joins(:custom_field_values).where(:network_id => nw.id, :key => User::CAMPUS_USER_CATEGORY, :custom_field_values => {:user_id => self.id, :value => "true"}).pluck("custom_fields.key") rescue nil
    categories = categories.keep_if { |k, v| cfs.include?(v.to_s) } if !cfs.blank? #21,22
    categories
  end

  def has_email_account?
    self.email_accounts.present? ? true : false
  end

  def get_report_topics(network)
    if network.is_admin?(self)
      return network.topics.where(:state => Topic::State.db_value(:active)).order("created_at DESC")
    elsif self.is_authorize_sender?(network.id)
      return Topic.where(state: Topic::State.db_value(:active), group_id: self.get_posting_group_ids(network.id)).order("created_at DESC")
    else
      return []
    end
  end

  def get_all_scheduled_messages(network, params=nil)
    conditions = []
    conditions << "scheduled_messages.scheduled_at > '#{Time.now}'"
    user_roles = self.roles(network)
    if user_roles.network_admin
      conditions << " groups.network_id = #{network.id} "
    elsif user_roles.location_admin
      group_ids = self.get_all_campus_admin_campuses_groups(network.id).pluck("groups.id")
      conditions << " scheduled_messages.group_id IN (#{group_ids.join(",")}) "
    elsif user_roles.group_admin
      group_ids = self.get_posting_group_ids(network.id).join(",")
      conditions << " scheduled_messages.group_id IN (#{group_ids}) "
    end
    sort_array = (params && params[:sort_by].present? && params[:sort].present?) ? "#{params[:sort_by]} #{params[:sort]}" : "scheduled_messages.scheduled_at DESC"
    conditions << " topics.subject like '%#{params[:search_key]}%' " if params[:search_key].present?
    ScheduledMessage.joins(:group, :topic).where(conditions.join(" AND ")).order(sort_array)
  end

  def get_standard_templates(network, params=nil, favorite = false)
    user_roles = self.roles(network)
    sort_array = (params && params[:sort_by].present? && params[:sort].present?) ? "#{params[:sort_by]} #{params[:sort]}" : "favorite desc, created_at desc"
    if user_roles.network_admin
      group_ids = UserGroup.fetch_user_groups({:conditions => [{:network_id => network.id}]}).pluck("groups.id")
      get_templates(network.id, self.id, group_ids, sort_array, params, favorite)
    elsif user_roles.location_admin
      group_ids = self.get_all_campus_admin_campuses_groups(network.id).pluck("groups.id")
      get_templates(network.id, self.id, group_ids, sort_array, params, favorite)
    elsif user_roles.group_admin
      group_ids = UserGroup.fetch_user_groups({:user => self, :conditions => ["user_groups.administrator = 1 and user_groups.can_post =1", {:network_id => network.id}]}).pluck("groups.id")
      get_templates(network.id, self.id, group_ids, sort_array, params, favorite)
    else
      conditions = "user_id = '#{self.id}' and network_id = '#{network.id}' "
      conditions += " and name like '%#{params[:search_key]}%' " if params && params[:search_key].present?
      conditions += " and favorite = 1 " if favorite
      SavedMessage.where(conditions).order(sort_array)
    end
  end

  def get_templates(nid, uid, group_ids, sort_array, params=nil, favorite)
    conditions = "network_id = '#{nid}' "
    conditions += " and name like '%#{params[:search_key]}%' " if params && params[:search_key].present?
    conditions += " and favorite = 1 " if favorite
    if group_ids.size > 0
      SavedMessage.where(conditions).order(sort_array).select { |t| t.user_id == uid or t.save_for == :all or (t.save_for == :groups and !(t.group_ids ? t.group_ids.split(",").collect(&:to_i) : [] & group_ids).empty?) }
    else
      SavedMessage.where(conditions).order(sort_array).select { |t| t.user_id == uid or t.save_for == :all }
    end
  end

  def get_all_pending_topic_requests(network, params=nil)
    user_roles = self.roles(network)
    conditions = []
    if user_roles.network_admin
      conditions << " groups.network_id = #{network.id} "
    elsif user_roles.location_admin
      group_ids = self.get_all_campus_admin_campuses_groups(network.id).pluck("groups.id")
      conditions << " pending_topic_requests.group_id IN (#{group_ids.join(",")}) "
    elsif user_roles.group_admin
      group_ids = self.get_posting_group_ids(network.id).join(",")
      conditions << " pending_topic_requests.group_id IN (#{group_ids}) "
    end
    sort_array = (params && params[:sort_by].present? && params[:sort].present?) ? "#{params[:sort_by]} #{params[:sort]}" : "pending_topic_requests.created_at DESC"
    conditions << " topics.subject like '%#{params[:search_key]}%' " if params[:search_key].present?
    PendingTopicRequest.joins(:group, :topic => :started_by).where(conditions.join(" AND ")).order(sort_array)
  end

  def user_posts(nid, gid=nil)
    if !gid.blank?
      Topic.where(:started_by_id => self.id, :network_id => nid, :group_id => gid).count rescue 0
    else
      Topic.where(:started_by_id => self.id, :network_id => nid).count rescue 0
    end
  end

  # Defining class methods
  class << self

    # Method to authenticate a user at LDAP server.
    #
    # Parameters :
    #
    #:: * *field*
    #:: * *password*
    #:: * *login_type*
    #:: * *ldap_server* ( can be nil )
    def authenticate(field, password, login_type, ldap_server = nil, s_code=nil, no_email=false)
      Rails.logger.debug "called with #{field} and #{password}"
      if no_email
        u = User.joins(:phone_numbers, :user_networks).where("phone_numbers.number = ? and user_networks.security_code = ? and user_networks.verified=true", field, s_code).first
        u.set_encrypted_password if u.present?
      else
        ldap = Auth::LDAP::LDAP.new
        begin
          email = Mail::Address.new(field.gsub("\"", ""))
          raise Mail::Field::ParseError if (email && !email.kind_of?(Mail::Address))
          domain = email.domain
          result = ldap.authenticate(field, password, nil, domain) if LDAP_DOMAIN.include?(domain)
          return result if result
        rescue Mail::Field::ParseError
          Rails.logger.debug "Invalid Email address detected. Look for login field"
        end
        Rails.logger.error("ldap : #{ldap_server}")

        # if ldap_server
        #   nw_login = "#{ldap_server}-#{field}"
        #   @u = User.where(['email = ?', field]).first
        #   @u = User.joins(:user_logins).where(:user_logins => {:network_login => "#{nw_login}"}).readonly(false).first if @u.nil?
        # else
        #   @u = User.where(['email = ? or login = ?', field, field]).first
        # end
        # if @u.nil?
        #   em = EmailAccount.where(:email => field).first
        #   @u = em.user if em
        # end

        if ldap_server
          nw_login = "#{ldap_server}-#{field}"
          u = User.joins(:user_logins).where(:user_logins => {:network_login => "#{nw_login}"}).readonly(false).first if u.nil?
        end

        if u.nil?
          em = EmailAccount.where(:email => field, :primary => true).first
          u = em.user if em
        end
        u.set_encrypted_password if u.present?
        if (u or ldap_server.eql? 'ntcc') && ldap_server && (LDAP_SERVER+LDAP_SERVER_FULL_SITE).include?(ldap_server)
          result = ldap.authenticate(field, password, login_type, ldap_server, false)
          ####Uncomment this line if we need to inspect the LDAP result########
          #Merb.logger.error("result: #{result.inspect}")
          if result
            return result
          elsif !ldap_server.eql? 'cfcc'
            return false
          end
        end
      end
      un = nil
      if u && ldap_server && !"www".eql?(ldap_server)
        un = UserNetwork.joins(:network).where(:networks => {:coded_name => ldap_server}, :user_id => u.id).first
        if !un
          u.errors.add(:login, "You do not belong to this network")
          return u
        end
      end
      if no_email
        if u.present?
          un1 = UserNetwork.where(:user_id => u.id, :security_code => s_code).first
          u.errors.add(:base, "Invalid security code") if un && un1 && un1.id != un.id
          u.errors.add(:base, "Invalid phone or password.") if (!u.valid_password?(password) || (un && !un.security_code.eql?(s_code)))
        end
      else
        u.errors.add(:base, "Your email or Password are incorrect.") if (u.present? && !u.valid_password?(password))
      end
      return u.present? ? u : false
      # return ( @u && @u.cleartext_password == password)  ? @u : false
    end

    def get_all_network_admins
      query = "select * from user_networks un inner join users u on un.user_id = u.id and un.administrator = 1"
      User.find_by_sql(query)
    end

    def get_all_group_admins
      query = "select * from user_groups ug inner join users u on ug.user_id = u.id and ug.administrator = 1 and ug.can_post = 1 and ug.can_approve_topics = 1 and ug.can_approve_members = 1 and ug.can_authorize_users = 1 and ug.can_manage_users = 1  and ug.can_edit_group = 1 "
      User.find_by_sql(query)
    end

    def get_group_users(gid, params, network)
      group_users_ids = User.find_by_sql("select distinct u.id from user_groups ug inner join users u on ug.user_id = u.id  where ug.group_id = '#{gid}'")
      return nil unless group_users_ids.present?
      User.find_users(params, network, group_users_ids, "user_groups", gid)
    end

    def get_all_networks_users(network, params)
      if ["regroup-india", "wilmu"].include?(network.coded_name) && params[:hours].present?
        user_ids = User.find_by_sql("select distinct u.id from user_networks un inner join users u on un.user_id = u.id left outer join email_accounts ea on ea.user_id = u.id left outer join phone_numbers ph on ph.user_id = u.id where un.network_id = '#{network.id}' and ((ea.edited_at > '#{Time.now - params[:hours].to_i.hours}' and ea.edited_at IS NOT NULL) OR (ph.edited_at > '#{Time.now - params[:hours].to_i.hours}' and ph.edited_at IS NOT NULL))")
        return nil unless user_ids.present?
        User.find_users(params, network, user_ids, "user_networks")
      else
        network_users_ids = User.find_by_sql("select u.id from user_networks un inner join users u on un.user_id = u.id  where un.network_id = '#{network.id}'")
        return nil unless network_users_ids.present?
        User.find_users(params, network, network_users_ids, "user_networks")
      end
    end

    def find_users params, network, user_ids, from, gid=nil
      offset = 1
      users = []
      if !params[:limit].present? && user_ids.size > 1000
        offset = (user_ids.size/1000.0).ceil if user_ids.size > 0
      end
      offset.times do |n|
        query = User.build_query(params, network, from, n, gid, user_ids)
        User.find_by_sql(query).each { |user| users << user } unless query.nil?
      end
      users
    end

    def build_query(params, network, from, n, gid=nil, updated_ids=nil)
      limit = params[:limit].present? ? params[:limit].to_i : 1000
      query = "select u.first_name as firstName, IFNULL(u.last_name, '') as lastName, "
      query += "IFNULL(u.street_address, '') as street_address, IFNULL(u.city, '') as city, IFNULL(u.state, '') as state, IFNULL(u.zip, '') as zip," if network.map_mode
      query += "IFNULL(group_concat(distinct concat(IFNULL(cf.key, ''), '|', IFNULL(cfv.value, '')) SEPARATOR ';'), '') as 'customFields', " if network.custom_fields.present?
      query += "IFNULL(group_concat(distinct camp.name SEPARATOR ';'), '') as campusName, " if network.enable_campus
      case from
        when "user_networks"
          query += "IFNULL(group_concat(distinct ea.email order by ea.email = u.email desc SEPARATOR ';'), '') as email, "+
              "IFNULL(group_concat(distinct(substr(ul.network_login,LENGTH('#{network.coded_name}-')+1)) SEPARATOR ';'), '') as userID, "+
              "IFNULL(group_concat(distinct concat(ph.number, concat('|', IFNULL(ph.carrier, '')),concat('|', ph.type), concat('|', IFNULL(ph.country_code, '')), concat('|', case ph.designation when 1 then 'home' when 2 then 'work' when 3 then 'cell' when 4 then 'other' end)) SEPARATOR ';'), '') as 'phone', "+
              "IFNULL(group_concat(distinct (case when g.network_id=un.network_id then ug.group_id else NULL end) SEPARATOR ';'), '') as groupID, IF(LOCATE('#{network.coded_name}-', u.external_db_id)=1,IFNULL(substr(u.external_db_id,LENGTH('#{network.coded_name}-')+1), ''),'') as databaseID "
          query += "from user_networks un inner join users u on un.user_id = u.id "
          query += "left outer join custom_fields cf on cf.network_id = un.network_id left outer join custom_field_values cfv on cfv.custom_field_id = cf.id and cfv.user_id = u.id " if network.custom_fields.present?
          query += "left outer join campuses_user_networks cun on cun.user_network_id = un.id left outer join campuses camp on camp.id = cun.campus_id " if network.enable_campus
          query += "left outer join email_accounts ea on ea.user_id = u.id left outer join phone_numbers ph on ph.user_id = u.id left outer join user_logins ul on ul.user_id = u.id and ul.network_login like '#{network.coded_name}-%' left outer join user_groups ug on ug.user_id = u.id "
          query += "left outer join groups g on g.id = ug.group_id "
          if ["regroup-india", "wilmu"].include?(network.coded_name) && params[:hours].present?
            query += "where u.id in(#{updated_ids.map(&:id).join(",")}) "
          else
            query += "where un.network_id = '#{network.id}' "
          end
          query += "and un.administrator = 1 " if params[:networkAdmins].eql?("true")
          query += "and ug.user_id IS NULL " if params[:groupID].eql?("null")
          if network.enable_campus && params[:locationName].present?
            if params[:locationName].eql?("null")
              query += "and cun.id IS NULL "
            else
              query += "and camp.coded_name in('#{params[:locationName].gsub(",", "','")}') "
            end
          end
        when "user_groups"
          query += "IFNULL(group_concat(distinct ea.email order by ea.email = u.email desc SEPARATOR ';'), '') as email, "+
              "IFNULL(group_concat(distinct(substr(ul.network_login,LENGTH('#{network.coded_name}-')+1)) SEPARATOR ';'), '') as userID, "+
              "IFNULL(group_concat(distinct concat(ph.number, concat('|', IFNULL(ph.carrier, '')),concat('|', ph.type), concat('|', IFNULL(ph.country_code, '')), concat('|', case ph.designation when 1 then 'home' when 2 then 'work' when 3 then 'cell' when 4 then 'other' end)) SEPARATOR ';'), '') as 'phone', "+
              "IFNULL(group_concat(distinct ug.group_id SEPARATOR ';'), '') as groupID, IF(LOCATE('#{network.coded_name}-', u.external_db_id)=1,IFNULL(substr(u.external_db_id,LENGTH('#{network.coded_name}-')+1), ''),'') as databaseID "
          query += "from user_groups ug inner join users u on ug.user_id = u.id "
          query += "left outer join groups g on g.id = ug.group_id " if network.custom_fields.present? || network.enable_campus
          query += "left outer join custom_fields cf on cf.network_id = g.network_id left outer join custom_field_values cfv on cfv.custom_field_id = cf.id and cfv.user_id = u.id  " if network.custom_fields.present?
          query += "left outer join campuses_groups cg on cg.group_id = g.id left outer join campuses camp on cg.campus_id = camp.id " if network.enable_campus
          query += "left outer join email_accounts ea on ea.user_id = u.id left outer join phone_numbers ph on ph.user_id = u.id left outer join user_logins ul on ul.user_id = u.id and ul.network_login like '#{network.coded_name}-%' "
          query += "where ug.group_id = '#{gid}' "
          if network.enable_campus && params[:locationName].present?
            if params[:locationName].eql?("null")
              query += "and cg.id IS NULL "
            else
              query += "and camp.coded_name in('#{params[:locationName].gsub(",", "','")}') "
            end
          end
      end
      query += "and ug.administrator = 1 and ug.can_post = 1 and ug.can_approve_topics = 1 and ug.can_approve_members = 1 and ug.can_authorize_users = 1 and ug.can_manage_users = 1  and ug.can_edit_group = 1 " if params[:groupAdmins].eql?("true")
      query += "and ug.administrator = 1 and ug.can_post = 1 and ug.can_approve_topics = 1 and ug.can_approve_members = 1 and ug.can_authorize_users = 1 and ug.can_manage_users = 0  and ug.can_edit_group = 0 " if params[:limitedAdmins].eql?("true")
      query += "and ug.administrator = 1 and ug.can_post = 1 and ug.can_approve_topics = 0 and ug.can_approve_members = 0 and ug.can_authorize_users = 0 and ug.can_manage_users = 0  and ug.can_edit_group = 0 " if params[:authorizedSenders].eql?("true")
      query += "and u.updated_at > '#{Time.now - 24.hours}' " if params[:last24].eql?("true")

      if params[:email].present?
        query += "and ea.email in('#{params[:email].gsub(",", "','").gsub(" ", "+")}') "
        params[:mail_type] = ['1', '2', '3'].include?(params[:mail_type]) ? params[:mail_type] : '1'
        query += "and ea.primary = #{ {"1" => '1', '2' => '0'}[params[:mail_type]] } " if params[:mail_type] != '3'
      end

      query += "and ul.network_login in('#{network.coded_name}-#{params[:userID].gsub(",", "','#{network.coded_name}-")}')" if params[:userID].present?
      query += "and u.external_db_id in('#{network.coded_name}-#{params[:databaseID].gsub(",", "','#{network.coded_name}-")}')" if params[:databaseID].present?
      query += "and ((ea.updated_at > '#{Time.now - params[:hours].to_i.hours}' and ea.source = 2) OR (ph.updated_at > '#{Time.now - params[:hours].to_i.hours}' and ph.source = 2)) " if params[:hours].present?
      if network.custom_fields.present?
        if params[:customField].present? && params[:customFieldValue].present?
          query += "and (cf.key like '#{params[:customField]}%' and cfv.value like '#{params[:customFieldValue]}%') "
        elsif params[:customField].present?
          query += "and (cf.key like '#{params[:customField]}%' and cfv.value IS NOT NULL ) "
        elsif params[:customFieldValue].present?
          query += "and cfv.value like '#{params[:customFieldValue]}%' "
        end
      end
      query += "group by u.id order by u.first_name "
      query += "limit #{limit} "
      query += "offset #{(n * limit)}"
    end

    def import_ad_group_users ad_users, group, network_id, api_key, network_name
      if (g = Group.where(:name => group.cn, :network_id => network_id).first)
        user_xml = get_user_xml ad_users, g.id, network_name
        response = HTTParty.post("https://#{DOMAIN_NAME}/api/v1/users?api_key=#{api_key}",
                                 :body => user_xml.target!,
                                 :headers => {'Content-Type' => 'application/xml'})
      end
    end

    def compact_phones(homephone, mobile, ipphone)
      phones = [homephone, mobile, ipphone]
      phones = phones.uniq.compact.reject(&:blank?)
      phone_str = ""
      if phones.size == 1
        phone_str += "#{phones[0]}||||cell;"
      elsif phones.size == 2
        desig = (phones[0].eql?(ipphone) && (ipphone.eql?(mobile) || ipphone.eql?(homephone))) ? "work" : "cell"
        phone_str += "#{phones[0]}||||#{desig};"
        desig = (phones[1].eql?(ipphone) && (ipphone.eql?(mobile) || ipphone.eql?(homephone))) ? "work" : "cell"
        phone_str += "#{phones[1]}||||#{desig};"
      elsif phones.size == 3
        phone_str += homephone ? "#{homephone}||||home;" : ""
        phone_str += mobile ? "#{mobile}||||cell;" : ""
        phone_str += ipphone ? "#{ipphone}||||work" : ""
      end
    end

    def get_user_xml ad_users, g_id, network_name
      xml = ::Builder::XmlMarkup.new
      xml.users(:type => 'array') do
        ad_users.each do |ad_user|
          if ad_user[:givenname].is_a?(Array)
            gn = ad_user[:givenname].first
            sn = ad_user[:sn].first
            mail = ad_user[:mail].first
            unless "okwu".eql? network_name
              hp = ad_user[:homephone].first
              mp = ad_user[:mobile].first
              ipp = ad_user[:ipphone].first
            end
            sam = ad_user[:samaccountname].first
          else
            gn = ad_user[:givenname]
            sn = ad_user[:sn]
            mail = ad_user[:mail]
            unless "okwu".eql? network_name
              hp = ad_user[:homephone]
              mp = ad_user[:mobile]
              ipp = ad_user[:ipphone]
            end
            sam = ad_user[:samaccountname]
          end
          xml.user do
            xml.firstName gn
            xml.lastName sn
            xml.email mail
            unless "okwu".eql? network_name
              phones = compact_phones(hp, mp, ipp)
              xml.phone phones
            end
            xml.userID sam
            xml.groupID g_id
          end if ad_user
        end
      end
      xml
    end

    def post_xml(users, network)
      builder = Nokogiri::XML::Builder.new do |xml|
        xml.users(type: "array") {
          users.each do |user|
            xml.user {
              xml.email user[:email]
              xml.first_name user[:first_name]
              xml.last_name user[:last_name]
              xml.groupID user[:group_ids]
              xml.phone user[:number]
              xml.databaseID user[:databaseID]
            }
          end
        }
      end
      resp = HTTParty.post("https://#{SERVER}/api/v2/users?api_key=#{network.api_key}",
                           :body => builder.to_xml,
                           :headers => {'Content-Type' => 'application/xml'})
      return resp["response"]
    end

    # Added method to use it in common place send ad hoc and confirmation count
    def get_ad_hoc_message_users(csv_file_data, network)
      case csv_file_data.headers[0]
        when "email"
          users = EmailAccount.where(:email => csv_file_data["email"].compact.collect(&:strip), :primary => 1).pluck(:user_id).uniq
          ::Rails.logger.error "Email Users: #{users}"
        when "username"
          all_un = []
          csv_file_data["username"].each { |un| all_un << "#{network.coded_name}-#{un}" }
          ::Rails.logger.error all_un
          users = UserLogin.where(:network_login => all_un.compact.collect(&:strip)).pluck(:user_id).uniq
          ::Rails.logger.error users
        when "db_id"
          all_dbid = []
          csv_file_data["db_id"].each { |dbid| all_dbid << "#{network.coded_name}-#{dbid}" }
          ::Rails.logger.error all_dbid
          users = User.where(:external_db_id => all_dbid.compact.collect(&:strip)).pluck(:id).uniq
          ::Rails.logger.error users
      end
      return users
    end

    # Added method to use it in common place send ad hoc and confirmation count
    def get_send_dynamic_alert_users(csv_file_data, network)
      case csv_file_data.headers[0]
        when "email"
          users = User.joins(:email_accounts).where("email_accounts.email" => csv_file_data["email"].compact.collect(&:strip), "email_accounts.primary" => 1).uniq
        when "userID"
          all_uids = []
          csv_file_data["userID"].each { |uid| all_uids << "#{network.coded_name}-#{uid}" }
          users = User.joins(:user_logins).where("user_logins.network_login" => all_uids.compact.collect(&:strip)).uniq
        when "databaseID"
          all_dbid = []
          csv_file_data["databaseID"].each { |dbid| all_dbid << "#{network.coded_name}-#{dbid}" }
          users = User.where(:external_db_id => all_dbid.compact.collect(&:strip)).uniq
      end
      return users
    end

  end


end

symbolize_enum_values(User)
