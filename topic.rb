require 'cgi'
require 'sms/sms'
# require 'tmail'
require 'util/fb_tweet'
require 'util/topic_util'
require 'messagynist/tmail_extensions'
require 'util/topic_post'
require 'util/glock'
require 'util/litmus_api'
require 'util/call_fire'
require 'util/cdyne_voice'
require 'util/push_notification'
require 'iconv'
require 'rcap'

class Topic < ActiveRecord::Base
  include SMS
  include FbTweet
  include TopicUtil
  include TMailExtensions
  include TopicPost
  include GLock
  include RCAP::CAP_1_2

  # Added for xss security
  xss_terminate :except => [:spark, :original_body, :body]

  attr_accessor :save_template, :edit_template, :topic_files, :skip_callback
  attr_accessor :map_info, :map_alert, :map_removed_users, :no_email
  attr_accessor :business_address, :personal_address

  serialize :broadcast_group_ids, Array
  serialize :broadcasted_group_ids, Array
  serialize :alertus_group, Array
  serialize :related_topic_ids, Array

  # Enum attributes
  enumerate :source do
    value :id => 1, :name => :web
    value :id => 2, :name => :mobile
    value :id => 3, :name => :partner
    value :id => 4, :name => :migrated
    value :id => 5, :name => :admin
    value :id => 6, :name => :testing
    value :id => 7, :name => :api
  end

  enumerate :state do
    value :id => 1, :name => :active
    value :id => 2, :name => :pending
  end

  enumerate :post_type do
    value :id => 1, :name => :web_only
    value :id => 2, :name => :web_email
    value :id => 3, :name => :web_sms
    value :id => 4, :name => :web_email_sms
    value :id => 5, :name => :map
  end

  enumerate :reply_to do
    value :id => 1, :name => :group
    value :id => 2, :name => :author
    value :id => 3, :name => :custom
    value :id => 4, :name => :blank
    value :id => 5, :name => :owner
  end

  enumerate :vendor do
    value :id => 1, :name => :callfire
    value :id => 2, :name => :cdyne
  end

  enumerate :email_svc do
    value :id => 1, :name => :regroup
    value :id => 2, :name => :mailgun
  end

  MEDIAS = ["Web", "Email", "TTS", "TextSMS", "Twitter", "Facebook", "Map", "AlertManager", "API"]

  MEDIAS_NEW = [["Email", "Email"], ["Text-to-Speech (TTS)", "TTS"], ["SMSText Message", "TextSMS"], ["Twitter", "Twitter"], ["Facebook", "Facebook"], ["Map", "Map"], ["AlertManager", "AlertManager"], ["API", "API"]]
  TYPES = [['Scheduled', 'scheduled'], ['Multiple Groups', 'multiple']]
  # Associations
  belongs_to :network
  belongs_to :group
  belongs_to :template, :class_name => 'SavedMessage', :foreign_key => :template_id
  belongs_to :started_by, :class_name => 'User', :foreign_key => :started_by_id
  belongs_to :most_recent_editor, :class_name => 'User', :foreign_key => :most_recent_editor_id

  has_many :fbposts
  has_many :topic_histories
  has_many :aliases, :class_name => 'TopicAlias'
  has_many :comments
  # has_many :email_logs
  # has_many :topic_files
  has_many :files, :class_name => 'TopicFile'
  # has_many :voice_statuses, :foreign_key => :message_id, :class_name => 'VoiceStatus', :conditions => {:type => :tts}
  has_many :smtp_topics

  has_one :scheduled_message
  has_one :map, :class_name => 'MapInfo'
  has_one :pending_request, :class_name => 'PendingTopicRequest' #, :constraint => :skip
  has_one :campaign_info, :class_name => 'CampaignInfo'
  has_one :feature, :class_name => "FeatureTopic"
  has_one :smpp_alert, dependent: :destroy
  has_one :phone_alert, :class_name => "VoiceAlert", dependent: :destroy
  has_many :social_network_posts, :as => :post
  has_many :topic_costs
  has_one :topic_informacast_option, dependent: :destroy
  has_one :blaze_cast, dependent: :destroy
  has_one :message_count, :as => :message
  has_one :topic_email_stat


  POST_VIA = {Email: 1, SMS: 2, TTS: 4, Facebook: 8, AlertManager: 16}

  # searchable do
  #   string  :state
  #   boolean :voice_alert
  #   time    :scheduled_at do
  #     scheduled_message.scheduled_at if scheduled_message
  #   end
  #   string  :post_type, :multiple => true
  #   integer :network_id
  #   string  :coded_subject
  #   time    :created_at
  # end

  scope :sent_emails, lambda { |time|
    joins("left outer join scheduled_messages sm on topics.id = sm.topic_id").
      where("sm.scheduled_at <= '#{time}' or sm.id IS NULL").
      where("topics.state = #{Topic::State.db_value(:active)}").select("distinct topics.*")
  }

  scope :sent_tts, lambda { |time|
    joins("left outer join scheduled_messages sm on topics.id = sm.topic_id").
      where("sm.scheduled_at <= '#{time}' or sm.id IS NULL").
      where("topics.voice_alert = #{true} and topics.state = #{Topic::State.db_value(:active)}").select("distinct topics.*")
  }

  scope :report_topics, lambda { |time, query|
    sent_emails(time).where("subject like '%#{query}%'").order("topics.created_at desc")
  }

  scope :sent_via, lambda { |sent_via, user_id|
    query = scoped
    return query.scoped if sent_via.blank?
    conditions = {}
    join_tables = []
    sent_via.each do |media|
      case media
      when "Web"
        conditions = conditions.merge(:post_type => [Topic::PostType.db_value(:web_only), Topic::PostType.db_value(:web_email),
            Topic::PostType.db_value(:web_sms), Topic::PostType.db_value(:web_email_sms)])
      when "Email"
        conditions = conditions.merge(:post_type => [Topic::PostType.db_value(:web_email), Topic::PostType.db_value(:web_email_sms)])
      when "TTS"
        conditions = conditions.merge(:voice_alert => true)
      when "TextSMS"
        join_tables << :smpp_alert
      when "Twitter"
        conditions = conditions.merge(:publish_to_twitter => true)
      when "Facebook"
        conditions = conditions.merge(:publish_to_facebook => true)
        # is_posted_to_facebook? For moderatated group.
      when "Map"
        join_tables << :group
        conditions = conditions.merge(:groups => {:map_alert => true})
      when "AlertManager"
        conditions = conditions.merge(:push_notification => true)
      when "API"
        conditions = conditions.merge(:source => Topic::Source.db_value(:api))
      when 'multiple'
        query = query.having("count(topics.id) > 1")
      when 'scheduled'
        join_tables << :scheduled_message
      when 'admin'
        join_tables << {:group => :user_groups}
        conditions = conditions.merge(:user_groups => {:user_id => user_id, :administrator => true, :can_authorize_users => true})
      end
    end
    query = query.joins(join_tables).where(conditions)
    query.scoped
  }

  scope :none, where(:id => 0)
  scope :include_data, includes(:scheduled_message, :smpp_alert, :group, :started_by)
  # To get the campus group topics
  scope :campus_topics, lambda { |campus_group_ids| where(:group_id => campus_group_ids) }

  scope :group_by_topics, lambda { |group_ids| where(:group_id => group_ids) }
  # filters
  before_validation :encode_subject
  before_validation do
    self.network_id = self.group.network_id if self.group
  end
  before_validation :set_started_by, :record_spark #,:alias_old_subject
  before_save :set_email_options
  # before_save :sanitize_content
  before_create do
    self.ip = ENV["remote_ip"] || ""
  end
  validates :message_id, :uniqueness => {:case_sensitive => false, :scope => :group_id},
    :allow_nil => true, :if => "!original_body.nil?"

  # Validations
  validate :check_posting_privileges #validates_with_method :group_id, :check_posting_privileges
  # validates :body, :length => { :maximum => 65535 }
  validates :subject, :current_revision, :presence => true

  def display_name
    "ID##{self.id}: #{self.subject}"
  end

  def voice_statuses
    VoiceStatus.where(:message_type => VoiceStatus::MESSAGE_TYPE[:tts], :message_id => self.id)
  end

  def save_topic_files(t_files=nil)
    if !t_files.blank?
      for topic_file in t_files
        tf = TopicFile.new(:filename => topic_file.original_filename, :content_type => topic_file.content_type, :topic_id => self.id, :size => topic_file.size)
        tf.tempfile = topic_file.tempfile
        tf.save
      end
    end
  end

  def set_email_options
    ::Rails.logger.info "setting email options"
    if !self.original_body.blank?
      begin
        h = self.get_from_email_options
        self.from_name = h[:from_name]
        self.from_email = h[:from_email]
        self.reply_to_text = h[:reply_to_text]
        self.reply_to = h[:reply_to]
      rescue => e
        ::Rails.logger.error e
      end
    end
  end

  def create_map_info
    Rails.logger.info "creating map info function"
    if [:map].include?(self.post_type)
      Rails.logger.info "true"
      @m = MapInfo.new(:topic_id => self.id, :polygon => self.map_info)
      @m.save
      Rails.logger.info "save done #{@m.errors.inspect}"
    end
  end

  # Method to check if post will be multipe groups
  def is_multiple_post?
    !self.get_related_topic_ids.empty?
  end


  # Method to check if the topic is a scheduled one or not.
  def is_scheduled_post?
    scheduled_message.present?
  end

  #Method to check topic is posted to facebook or not
  def is_posted_to_facebook?
    social_network_posts.where(:social_network_name => "Facebook Profile").first
  end

  #Method to check topic is posted to facebook page or not
  def is_posted_to_facebook_page?
    social_network_posts.where(:social_network_name => "Facebook Page").first
  end

  # to get all remaining group ids once delete or reject moderated group ids the topics.
  def get_remaining_group_ids
    get_updated_brd_ids = self.is_scheduled_post? ? self.get_scheduled_updated_broadcast_group_ids : self.get_updated_broadcast_group_ids
    return get_updated_brd_ids.reject { |g| g.to_s == self.group_id.to_s }
  end

  # To get the current scheduled topic group ids.
  def get_related_scheduled_topic_group_ids
    self.get_related_topics.map(&:group_id) + [self.group_id]
  end

  # To get remaining scheduled post broadcast_group_ids
  def get_scheduled_updated_broadcast_group_ids
    broadcast_group_ids.select { |g| (Group.exists?(:id => g.to_i) && self.get_related_scheduled_topic_group_ids.include?(g.to_i)) }
  end

  # Method for update the scheduled broad cast ids while editing the scheduled messages
  def update_scheduled_broadcast_ids(topic_ids)
    updated_group_ids = self.get_scheduled_updated_broadcast_group_ids
    Topic.where(:id => topic_ids).each do |topic|
      topic.to_update_broadcast_group_ids(updated_group_ids)
    end
  end

  # To get updated broadcasted ids if any group deleted
  def get_updated_broadcast_group_ids
    broadcast_group_ids.select { |g| Group.exists?(:id => g.to_i) }
  end

  # Common method to use update the broadcast_group_ids and group_ids while deleting topic or editing the schedule message
  def to_update_broadcast_group_ids(updated_group_ids)
    self.skip_callback = true
    self.scheduled_message.update_attribute(:group_ids, updated_group_ids) if self.is_scheduled_post?
    self.update_attribute(:broadcast_group_ids, updated_group_ids)
    if self.smpp_alert.present?
      self.smpp_alert.update_attribute(:group_ids, updated_group_ids)
      self.smpp_alert.scheduled_text.update_attribute(:group_ids, updated_group_ids) if self.smpp_alert.scheduled_text.present?
    end
  end

  # Updating the broadcast_group_ids and smpp alert group ids while deleting the topic.
  # We should not update the open group and non-scheduled topic group ids.
  # We have to update the moderated and pending topics and before scheduled time topic group ids.
  def update_broadcast_group_ids_and_smpp_alert_group_ids
    unless self.get_related_topics.empty?
      begin
        updated_group_ids = []
        if (self.group.need_review && self.is_pending?) || self.is_scheduled_post?
          updated_group_ids = self.get_remaining_group_ids
        else
          updated_group_ids = self.get_updated_broadcast_group_ids
        end
        self.get_related_topics.each do |topic|
          unless updated_group_ids.empty?
            topic.to_update_broadcast_group_ids(updated_group_ids)
          end
        end
      rescue => e
        ::Rails.logger.error "Error with updating broadcast groups : #{e}"
      end
    end
  end

  # Method to excludes the blank files from the files passed in parameter.
  #
  # Parameters :
  # * *files*
  def topic_files=(files)
    @topic_files = (files.blank? ? nil : files)
    @topic_files = [files] if not files.blank? and not files.kind_of?(Array)
    @topic_files.reject! { |file| file.blank? } if @topic_files
  end

  # Method to initialize/save topic_files for a topic from the files.
  def set_files
    begin
      self.topic_files.each do |file|
        if file.kind_of?(Mail::Part)
          cid = file.content_id
          f = TopicFile.new({:filename => file.filename,
              :content_type => file.content_type, :size => file.decoded.length, :cid => cid})
          f.tempfile = file.body
          self.files << f
        else
          # self.files << TopicFile.new(file)
          tf = TopicFile.new(:filename => file.original_filename, :content_type => file.content_type, :size => file.size)
          tf.tempfile = file.tempfile
          self.files << tf
        end
      end if self.topic_files
    rescue => e
      ::Rails.logger.error e
    end
  end

  # Method to save the topic files for a topic to amazon server.
  def save_files
    self.files.each do |f|
      ::Rails.logger.error f.inspect
      ::AWS::S3::S3Object.store(f.filename,
        (f.tempfile.kind_of?(Mail::Body)) ? f.tempfile.decoded : f.tempfile.open, GlobalBucket,
        :access => :private) if f.tempfile
    end
  end

  # Method to set @publish_to_facebook variable.
  #
  # Parameters :
  #
  # * *var*
  def publish_to_facebook=(var)
    write_attribute(:publish_to_facebook, (var == "1" || var == "on" || var == true))
  end

  # Method to set @publish_to facebook_page variable.
  #
  # Parameters :
  #
  # * *var*
  def publish_to_facebook_page=(var)
    write_attribute(:publish_to_facebook_page, (var == "1" || var == "on"))
  end


  # Method to get the shorter subject for the topic.
  #
  # Parameters :
  #
  # * *len*
  def short_subject(len)
    (len - 4) > 0 ? subject[0..(len - 4)]+"..." : ""
  end

  # Method to shorten the text.
  #
  # Parameters :
  #
  # * *txt*
  # * *len*
  def short_text(txt, len)
    text = (len - 4) > 0 ? txt[0..(len - 4)]+"..." : ""
  end

  # Method to generate the text to be posted at twitter.
  # def twitter_text
  #   text = nil
  #   if self.group.standard_social_media?
  #     bitly_url = FbTweet.bitly_url("http://#{SERVER}#{Rails.application.routes.url_helpers.network_group_group_topic_path( self.network, self.group, self )}")
  #     prefix = (self.started_by ? self.started_by.get_full_name : (self.started_by_name || 'Anonymous'))+" posted \""
  #     suffix = "\" to the \""+self.group.name+"\" group. Check it out: #{bitly_url}"
  #     text = prefix+self.subject+suffix
  #     if text.length > FbTweet.tweet_size
  #       text = prefix+self.short_subject(FbTweet.tweet_size - prefix.length - suffix.length)+suffix
  #     end
  #   elsif self.group.body_social_media?
  #     if (self.body || self.original_body)
  #       if self.original_body
  #         # b = TMail::Mail.parse(self.original_body).actual_message
  #         b = Mail.new(self.original_body).actual_message
  #       elsif self.body
  #         b = self.body
  #       end
  #       text = self.short_text(Hpricot(b).inner_text, FbTweet.tweet_size)
  #     end
  #   else
  #     text = self.short_subject(FbTweet.tweet_size)
  #   end
  #   text
  # end

  def twitter_text
    text = nil
    if self.group.standard_social_media_twitter?
      host = self.group.network.coded_name
      if self.group.coded_name.eql?('tru')
        bitly_url = FbTweet.bitly_url("http://www.tru.ca/hsafety/emergency/trualerts.html")
      else
        bitly_url = FbTweet.bitly_url("http://#{host}.#{SERVER}#{Rails.application.routes.url_helpers.network_group_group_topic_path(self.network, self.group, self)}")
      end
      prefix = (self.started_by ? self.started_by.get_full_name : (self.started_by_name || 'Anonymous'))+" posted \""
      suffix = "\" to the \""+self.group.name+"\" group. Check it out: #{bitly_url}"
      text = prefix+self.subject+suffix
      if text.length > FbTweet.tweet_size
        text = prefix+self.short_subject(FbTweet.tweet_size - prefix.length - suffix.length)+suffix
      end
    elsif self.group.body_social_media_twitter?
      if (self.body || self.original_body)
        if self.original_body
          b = Mail.new(self.original_body).actual_message
        elsif self.body
          b = self.body
        end
        coder = HTMLEntities.new
        b = coder.decode(b)
        text = self.short_text(Hpricot(b).inner_text, FbTweet.tweet_size)
      end
    else
      text = self.short_subject(FbTweet.tweet_size)
    end
    text
  end

  # Method to generate text to be posted to Facebook.
  def facebook_text
    text = nil
    if self.group.standard_social_media_facebook?
      host = self.group.network.coded_name
      if self.group.coded_name.eql?('tru')
        bitly_url = FbTweet.bitly_url("http://www.tru.ca/hsafety/emergency/trualerts.html")
      else
        bitly_url = FbTweet.bitly_url("https://#{host}.#{SERVER}#{Rails.application.routes.url_helpers.network_group_group_topic_path(self.network, self.group, self)}")
      end
      text = "Posted \"#{self.subject}\" to the \"#{self.group.name}\" group. Please click \"Check it out!\" below for more details."
    elsif self.group.body_social_media_facebook?
      if (self.body || self.original_body)
        if self.original_body
          b = Mail.new(self.original_body).actual_message
        elsif self.body
          b = self.body
        end
        coder = HTMLEntities.new
        b = coder.decode(b)
        text = Hpricot(b).inner_text
      end
    else
      text = self.subject
    end
    text
  end

  # Fetch the Twitter profiles and pages
  def fetch_twitter_accounts_count
    network_twitter_count = (self.current_topic_sent_group_ids.blank? && self.network.has_twitter_account?) ? 1 : 0
    (self.group.has_twitter_account? ? 1 : 0) + network_twitter_count
  end

  # Fetch the Facebook profiles and pages
  def fetch_fb_profiles_and_pages(count=false)
    network_fb_profiles = []
    network_fb_pages = []
    if self.current_topic_sent_group_ids.blank?
      network_fb_profiles = self.group.network.get_fb_profiles.where(:can_post => true)
      network_fb_pages = self.group.network.get_fb_pages
    end
    result = [fetch_fb_profiles + network_fb_profiles, fetch_fb_pages + network_fb_pages]
    return result.flatten.length if count
    result
  end

  def post_to_facebook
    link_txt = "Check it out!"
    host = self.group.network.coded_name
    fb_text = self.facebook_text
    if self.group.coded_name.eql?('tru')
      link = "http://www.tru.ca/hsafety/emergency/trualerts.html"
    else
      link = "https://#{host}.#{SERVER}#{Rails.application.routes.url_helpers.network_group_group_topic_path(self.network, self.group, self)}"
    end

    fb_profiles, fb_pages = fetch_fb_profiles_and_pages

    for fb_profile in fb_profiles
      if CommonMethods.is_valid_fb_access_token(fb_profile)
        fb_profile.publish_on_fb_profile(fb_text, link_txt, link)
        social_network_post_entry(fb_profile)
      end
    end

    for fb_page in fb_pages
      if CommonMethods.is_valid_fb_access_token(fb_page)
        fb_page.publish_on_fb_page(fb_text, link_txt, link)
        social_network_post_entry(fb_page)
      end
    end

  end

  def social_network_post_entry(source_obj, social_network_name = nil)
    social_network_name ||= source_obj.social_network_name
    reference = {"Facebook Profile" => "facebook_id", "Facebook Page" => "facebook_page_id"}
    social_network_post = SocialNetworkPost.new(:post_type => self.class.to_s, :post_id => self.id, :source_type => source_obj.class.to_s, :source_id => source_obj.id, :social_network_name => social_network_name, :reference => source_obj.send(reference[social_network_name]))
    social_network_post.save!
  end

  # Method to send standard text.
  def send_standard_text(body_text)
    ic_ignore = Iconv.new('US-ASCII//IGNORE', 'UTF-8')
    mail_body = body_text
    mail_body = mail_body.gsub("&nbsp;", "").gsub("&nbsp", "") if mail_body
    coder = HTMLEntities.new
    mail_body = coder.decode(mail_body)
    mail_body = Hpricot(mail_body).to_plain_text

    # send premium text if carrier is verizon
    #    v_phones = DataMapper.repository.adapter.query("select distinct concat(p.country_code, p.number) from phone_numbers p inner join user_groups ug on ug.user_id = p.user_id "+
    #        "where ug.group_id=#{self.group_id} and ug.receive_sms = 1 and p.type in(1, 3) and p.carrier = 'verizon'")
    #
    #    begin
    #      unless (v_phones && v_phones.empty?)
    #        started_by = self.started_by || self.group.user_group_administrators.first
    #        sms_text = ic_ignore.iconv((mail_body.size > 160) ? mail_body[0..159].gsub(/\r/," ").gsub(/\n/," ") : mail_body.gsub(/\r/," ").gsub(/\n/," "))
    #        smpp_alert = SmppAlert.new(:message => sms_text, :group_id => self.group.id, :user_id => started_by.id)
    #        smpp_alert.save_alert(v_phones, true)
    #      end
    #    rescue
    #    end
    #    # end send premium

    subject = "[#{self.group.name}] #{self.subject}"
    mail_body = (mail_body.length > 160) ? mail_body[0..(160 - subject.length + 10)] : mail_body #actual mail subject --> [Regroup] #{hash[:subject]}
    user = self.started_by || self.group.user_group_administrators.first
    email = Mail::Address.new(user.email)

    via_text = "Regroup"
    if "hindscc".eql?(self.group.network.coded_name)
      via_text = "HindsCC"
    end
    from = "#{self.posted_anonymously ? via_text : user.get_full_name + ' via '+via_text}"

    if !self.broadcast_group_ids.blank? && self.broadcast_group_ids.size > 1
      Resque.enqueue(EmailSender, {:subject => subject, :body => mail_body, :group => self.group.id, :user => user.id, :coded_subject => self.coded_subject, :topic => self.id, :from => from, :template => :email_sms, :broadcast_group_ids => self.broadcasted_group_ids, :count => -1, :via_text => via_text}) if self.no_email.nil? && !self.broadcasted_group_ids.blank?
      # StarlingQueue.set( OUTGOING_MAIL, { :subject => subject, :body => mail_body, :group => self.group.id , :user => user.id, :coded_subject => self.coded_subject, :topic => self.id, :from => from, :template => :email_sms, :broadcast_group_ids => self.broadcasted_group_ids, :count => -1, :via_text => via_text} ) if self.no_email.nil? && !self.broadcasted_group_ids.blank?
    else
      cnt = self.get_sms_count(self.group_id)
      cnt = (cnt / EMAIL_BATCH_SIZE.to_f).ceil if cnt > 0
      Resque.enqueue(EmailSender, {:subject => subject, :body => mail_body, :group => self.group.id, :user => user.id, :coded_subject => self.coded_subject, :topic => self.id, :from => from, :template => :email_sms, :count => cnt, :via_text => via_text}) if self.no_email.nil?
      # StarlingQueue.set( OUTGOING_MAIL, { :subject => subject, :body => mail_body, :group => self.group.id , :user => user.id, :coded_subject => self.coded_subject, :topic => self.id, :from => from, :template => :email_sms, :count => cnt, :via_text => via_text } ) if self.no_email.nil?
    end
  end

  # Method to send voice alert.
  def send_voice_alert
    begin
      g_ids = []
      if (!self.broadcast_group_ids.blank? && self.broadcast_group_ids.size > 1)
        if self.group.need_review && !(is_scheduled_post? && is_approved?)
          g_ids = self.get_sent_group_ids.join(',')
        else
          g_ids = self.get_open_and_approved_group_ids[0, self.get_open_and_approved_group_ids.index(self.group_id.to_s)].join(',')
        end
      end
      @phones = PhoneNumber.connection.execute("select distinct IF(country_code=1, concat(p.country_code, p.number), concat('011', p.country_code, p.number)) from phone_numbers p inner join user_groups ug on ug.user_id = p.user_id "+
          "where ug.group_id=#{self.group_id} and ug.receive_voice = 1 and p.designation in (#{self.designation}) and p.type in(2, 3) #{ g_ids.blank? ? "" : "and p.user_id not in (select user_id from user_groups where group_id in(#{g_ids}))"}").to_a.flatten
      Rails.logger.info("phones for topic at group #{self.group.id}: #{@phones.inspect}")
      if @phones.blank?
        self.update_column("campaign_status", "no_phones")
      else
        body_text = self.text_body
        cpm = @phones.size > 5000 ? 5000 : @phones.size
        if RegroupSystem.first.cdyne?
          CdyneVoice::send_tts(body_text, @phones, self.caller_id, self.id, self.caller_name)
          self.update_column(:vendor, 2)
        else
          cid, error = CallFire::xml_send_to_campaign(body_text, @phones, "[#{self.group.network.coded_name}]#{self.get_subject}", self.caller_id, cpm)
          if cid
            Topic.where(:id => self.id).update_all({:campaign_id => cid, :report_status => 0})
          else
            raise error ? error.message : "campaign_id is blank"
          end
        end
      end
      #      create_message_count("tts", @phones.size)
    rescue => e
      Rails.logger.error "Unable to post TTS. Error: #{e}"
      raise CustomException::TtsBatchFailure.new({"phones" => @phones, "message" => self.text_body, "topic_id" => self.id, "error_obj" => e, "time" => Time.now})
    end
  end

  def send_push_notification
    begin
      g_ids = []
      if (!self.broadcast_group_ids.blank? && self.broadcast_group_ids.size > 1)
        if self.group.need_review && !(is_scheduled_post? && is_approved?)
          g_ids = self.get_sent_group_ids.join(',')
        else
          g_ids = self.get_open_and_approved_group_ids[0, self.get_open_and_approved_group_ids.index(self.group_id.to_s)].join(',')
        end
      end
      #IOS
      device_tokens = UserDevice.connection.execute("select distinct device_token from user_devices ud inner join user_groups ug on ug.user_id = ud.user_id"+
          " where ug.group_id=#{self.group_id} and ud.device_type = 1 #{ g_ids.blank? ? "" : "and ud.user_id not in (select user_id from user_groups where group_id in(#{g_ids}))"}").to_a.flatten
      Rails.logger.error "Device Tokens: [#{device_tokens.inspect}]"
      device_tokens.each { |dt| PushNotification::send_pn("IOS", dt, self.subject, self.id) }

      #GCM
      device_tokens = UserDevice.connection.execute("select distinct device_token from user_devices ud inner join user_groups ug on ug.user_id = ud.user_id"+
          " where ug.group_id=#{self.group_id} and ud.device_type = 2 #{ g_ids.blank? ? "" : "and ud.user_id not in (select user_id from user_groups where group_id in(#{g_ids}))"}").to_a.flatten
      Rails.logger.info "Device Tokens: [#{device_tokens.inspect}]"
      PushNotification::send_pn("GCM", device_tokens, self.subject, self.id)

    rescue => e
      Rails.logger.error "Error sending Push Notification for topic #{self.id}: #{e.inspect}"
    end
  end

  def send_nortel_alert
    CallFire::xml_send_to_nortel(self.text_body, self.caller_id)
  end


  # Method to create alert us type of alert.
  # Parameters :
  #
  # * *profile_id*
  # * *message*
  # * *alertus_url*
  # * *alertus_groups*
  def create_alertus_alert(profile_id, message, alertus_url, alertus_groups)
    client = Savon.client(wsdl: alertus_url, headers: {"SOAPAction" => ""})
    p = client.call(:get_alert_profile, message: {arg0: profile_id})
    profile = p.body[:get_alert_profile_response][:return]
    coder = HTMLEntities.new
    message = coder.decode(message)
    alertus_data = {
      :alert_profile => profile,
      :text => message.gsub(/\r/, " ").gsub(/\n/, " ").gsub("_", " "),
      :sender => "#{self.started_by.email}",
      :client_name => "Regroup",
      :duration => "900000",
      :priority => "1"
    }
    if alertus_groups.include?("All")
      alertus_data = alertus_data.merge(
        {:command_recipients => {
            :address_mode => {:address_mode => "All", :id => "0"},
            :localization_mode => "0"
          }})
    else
      alertus_data = alertus_data.merge(
        {:command_recipients => {
            :address_mode_recipients => alertus_groups,
            :address_mode => {:address_mode => "Group", :id => "1"},
            :localization_mode => "0"
          }})
    end
    res = client.call(:dispatch_alertus_message, message: {:arg0 => alertus_data})
    Rails.logger.error "AlertUS Response: #{res.body}"
    self.update_attributes(:alertus_message_id => res.body[:dispatch_alertus_message_response][:return][:id])
  end

  # Method to send alertus type of alert.
  def send_alertus_alert
    begin
      if self.network && self.network.alertus_url
        self.alertus_group = ["all"] if (self.alertus_group.nil? || self.alertus_group.empty? || self.alertus_group.include?("all"))
        create_alertus_alert(self.alertus_profile, self.text_body, self.network.alertus_url, self.alertus_group)
      end
    rescue => e
      Rails.logger.error "Unable to post to Alertus. Error: #{e}"
    end
  end

  # Method to publish a message.
  #
  # Publishes at all the mentioned places.
  def publish_message
    unless (self.group.email_option && !self.group.email_option.frequency.eql?(:default))
      if (:web_email == self.post_type || :web_email_sms == self.post_type)
        self.update_column(:email_svc, Network::EmailSvc.db_value(self.network.email_svc))
        mail_sender = self.email_svc == :regroup ? EmailSender : EmailSenderMG
        started_by = self.started_by || self.group.user_group_administrators.first
        if !self.broadcast_group_ids.blank? && self.broadcast_group_ids.size > 1
          CampaignInfo.unpublished.size > 0 ? create_campaign : Resque.enqueue(TopicCreateCampaign, self.id)
          if group.need_review && !(is_scheduled_post? && is_approved?)
            # Additional check for keeping scheduled and approved posts out of this loop. They will be treated as open groups.
            cnt = self.fetch_emails.size
            cnt = (cnt / EMAIL_BATCH_SIZE.to_f).ceil if cnt > 0
            Resque.enqueue(mail_sender, {:subject => self.subject, :body => self.body, :group => self.group.id, :user => started_by.id, :coded_subject => self.coded_subject, :topic => self.id, :template => :broadcast, :count => cnt, :sent_group_ids => self.get_sent_group_ids}) if self.no_email.nil?
          else
            if self.broadcasted_group_ids.present? && self.no_email.nil?
              if self.broadcasted_group_ids.size == 1 && self.broadcasted_group_ids.first.eql?(self.group_id.to_s)
                cnt = self.get_email_count(self.group_id)
                cnt = (cnt / EMAIL_BATCH_SIZE.to_f).ceil if cnt > 0
              else
                cnt = -1
              end
              Resque.enqueue(mail_sender, {:subject => self.subject, :body => self.body, :group => self.group.id, :user => started_by.id, :coded_subject => self.coded_subject, :topic => self.id, :template => :broadcast, :count => cnt, :broadcast_group_ids => self.broadcasted_group_ids})
            end
          end
          Resque.enqueue(TopicBuildEmailLog, self.id) if self.email_svc == :regroup
        else
          cnt = self.email_count || self.get_email_count(self.group_id)
          cnt = (cnt / EMAIL_BATCH_SIZE.to_f).ceil if cnt > 0
          CampaignInfo.unpublished.size > 0 ? create_campaign : Resque.enqueue(TopicCreateCampaign, self.id)
          Resque.enqueue(mail_sender, {:subject => self.subject, :body => self.body, :group => self.group.id, :user => started_by.id, :coded_subject => self.coded_subject, :topic => self.id, :template => :broadcast, :count => cnt}) if self.no_email.nil?
          Resque.enqueue(TopicBuildEmailLog, self.id) if self.email_svc == :regroup
        end
      end
    end
    # if ( :web_sms == self.post_type || :web_email_sms == self.post_type )
    #   self.send_standard_text(self.body)
    # end
    begin
      # Twitter
      text = self.twitter_text rescue nil
      if text && self.publish_to_twitter && (self.group.has_twitter_account? || self.network.has_twitter_account?)
        Resque.enqueue(PublishTwitter, self.id, text)
      end
      #Facebook
      Resque.enqueue(PublishFacebook, self.id, self.publish_to_facebook, self.publish_to_facebook_page, self.publish_offline) if self.publish_to_facebook #(self.publish_to_facebook || self.publish_to_facebook_page || self.group.has_fb_account? || self.group.network.has_fb_account? )
      #Voice Alert
      Resque.enqueue(SendTts, self.id, self.original_body ? self.get_email_in_group_ids(:tts) : self.broadcast_group_ids, self.caller_id) if self.voice_alert && self.phone_alert.nil?
      #alertusAlert
      Resque.enqueue(SendAlertusAlert, self.id, self.alertus_profile, self.alertus_group) if self.alertus_alert
      #SmppAlert
      Resque.enqueue(SendSmppAlert, self.smpp_alert.id, self.original_body ? self.get_email_in_group_ids(:text) : self.broadcast_group_ids) if self.smpp_alert
      #VoiceAlert
      Resque.enqueue(SendVoiceAlert, self.phone_alert.id, self.phone_alert.group_ids) if self.phone_alert
      #NortelAlert
      Resque.enqueue(RenderThenCall, "send_nortel_alert", {:topic_id => self.id}) if self.nortel_alert
      #InformaCastAlert
      Resque.enqueue(SendInformacastAlert, self.id) if self.topic_informacast_option && self.topic_informacast_option.informacast_alert
      #Push Notifications
      self.send_push_notification if self.push_notification
      #Bell Commander Service Alert
      Resque.enqueue(SendBellcommanderServiceNotification, self.id) if self.bcs_alert
      #BlazeCast Alert
      Resque.enqueue(SendBlazeCastAlert, self.id) if self.blaze_cast && self.blaze_cast.alert
      #BRGAlert
      Resque.enqueue(RenderThenCall, "send_brg_alert", {:topic_id => self.id}) if self.brg_alert
      #OCTECH PA Alert
      Resque.enqueue(RenderThenCall, "send_octech_pa_alert", {:topic_id => self.id}) if self.octech_pa_alert
      #rSmart Alert
      Resque.enqueue(RenderThenCall, "send_rsmart_alert", {:topic_id => self.id}) if self.rsmart_alert?
      #Update stats
      Resque.enqueue(RenderThenCall, "update_stats", {:topic_id => self.id})
    rescue => e
      Rails.logger.error e.backtrace.join("\n")
      Rails.logger.error "Resque Enqueue Errror: #{e.inspect} for Topic: #{self.id}"
    end
  end

  def get_cal_email_count
    self.fetch_emails.size
  end

  def get_cal_sms_count
    self.smpp_alert.group_ids = self.original_body ? self.get_email_in_group_ids(:text) : self.broadcast_group_ids
    self.smpp_alert.smpp_phones.size
  end

  def get_tts_count
    self.broadcast_group_ids = self.original_body ? self.get_email_in_group_ids(:tts) : self.broadcast_group_ids
    g_ids = []
    if (!self.broadcast_group_ids.blank? && self.broadcast_group_ids.size > 1)
      if self.group.is_moderated? && !(is_scheduled_post? && is_approved?)
        g_ids = self.get_sent_group_ids.join(',')
      else
        g_ids = self.get_open_and_approved_group_ids[0, self.get_open_and_approved_group_ids.index(self.group_id.to_s)].join(',')
      end
    end
    @phones = PhoneNumber.connection.execute("select distinct IF(country_code=1, concat(p.country_code, p.number), concat('011', p.country_code, p.number)) from phone_numbers p inner join user_groups ug on ug.user_id = p.user_id "+
        "where ug.group_id=#{self.group_id} and ug.receive_voice = 1 and p.designation in (#{self.designation}) and p.type in(2, 3) #{ g_ids.blank? ? "" : "and p.user_id not in (select user_id from user_groups where group_id in(#{g_ids}))"}").to_a.flatten
    @phones.size
  end

  def sent_at
    if is_scheduled_post?
      sent_at = scheduled_message.scheduled_at
    elsif group.is_moderated?
      sent_at = Time.now
    else
      sent_at = created_at
    end
    sent_at
  end

  # Method to return the coded name for a network.
  def network_coded_name
    network.coded_name
  end

  def post_type=(val)
    if !val.blank?
      val = val.eql?("email") ? "web_email" : val
      write_attribute(:post_type, Topic::PostType.db_value(val.to_sym))
    end
  end

  # Method to find is the subject has already been taken in the group.
  def unique_in_group
    same_subject = Topic.where(:coded_subject => self.coded_subject, :group_id => self.group_id).where("id !=#{self.id}").first
    if not same_subject.nil?
      [false, "Message subject is already taken - <a href='http://#{SERVER}/#{same_subject.network.coded_name}/groups/#{same_subject.group.coded_name}/topics/#{same_subject.coded_subject}'>#{same_subject.subject}</a>"]
    else
      true
    end
  end

  # Method to check if a user have posting priviledges.
  def check_posting_privileges
    result = check_privileges(self.group, self.started_by, self.original_body, self.from_email)
    self.errors.add("group_id", result[1]) if result.class == Array
  end

  #  def publish_to
  #    text = " posted \""+subject+"\" to \""+group.name+"\" group. Please visit: http://www.regroup.com"
  #    fb_user = get_facebook_user(started_by.facebook_id)
  #    fb_user.publish_to(started_by.facebook_page_id, {:message => text})
  #  end


  # xss_terminate :sanitize => [:body, :subject, :spark]
  #copy started_by from most_recent_editor

  # Method to sanitize the content of a topic
  #
  # * *subject*
  # * *body*
  # * *spark*
  def sanitize_content
    return if self.group && !["utexas", "utbeta", "demo"].include?(self.group.network.coded_name)
    body.sanitize_html! if body
    spark.sanitize_html! if spark
  end

  # Method to save the topic history. Keeps a track of changes.
  def save_topic_history(*params)
    if self.body_dirty
      u = self.started_by ? User.find((self.most_recent_editor || self.started_by).id) : nil
      TopicHistory.create(:revision => self.current_revision, :subject => self.subject, :body => self.body, :topic => self, :user => u, :ip => self.ip)
    end
  end

  def set_started_by(context = :default)
    self.started_by ||= User.find(self.most_recent_editor.id) if self.most_recent_editor
  end

  # Method to set last subject for a topic.
  # Parameters :
  #
  # * *new_subject*
  def set_last_subject(new_subject)
    self.last_subject = self.subject # if attribute_dirty?(:subject) # I think this could fix the issue described in alias_old_subject
  end

  # Marks topic body as 'dirty'.
  def mark_body_dirty
    self.body_dirty = true
  end

  # copy body to spark if there is none
  def record_spark(context = :default)
    self.spark ||= body
  end

  # Method to set old subject for a topic.
  # Parameters :
  #
  # * *context* ( optional, default is :default)
  def alias_old_subject(context = :default)
    return if last_subject.nil?
    if not self.new_record? # NEED NEW CONDITION (probably) now that last_subject will always be true whether the name has changed or not # this is a rename, not a new topic
      @ta = TopicAlias.create(:coded_subject => last_subject.seoify, :network_id => network.id, :topic_id => self.id, :user_id => self.most_recent_editor.id)
    end
  end

  # Method to encode the subject for a topic.
  # Parameters :
  #
  # * *context* ( optional, default is :default)
  def encode_subject(context = :default)
    unless self.subject.blank?
      #      last_topic = Topic.first(:subject => self.subject )
      last_topic = Topic.where(["coded_subject = ? and group_id = ?  and id != ?", self.subject.seoify, self.group_id, self.id.to_i]).first
      if last_topic
        self.coded_subject = "#{self.subject.seoify}-#{Time.now.strftime('%Y%m%d%H%M%S')}"
      else
        self.coded_subject = self.subject.seoify
      end
    end unless self.coded_subject
  end

  # def remove_conflicting_alias(context = :default)
  #   @alias = TopicAlias.first :conditions => ['coded_subject = ? and network_id = ?', coded_subject, network.id]
  #   @alias.destroy if @alias
  # end

  # Method to get distinct sms addresses.
  def get_distinct_sms_addresses()
    #user_groups = UserGroup.all(:group_id => self.group_id, :receive_sms => true, UserGroup.user.phone.not => nil,
    #  UserGroup.user.carrier.not => nil)
    user_groups = PhoneNumber.find_by_sql("select p.number, p.carrier from phone_numbers p inner join user_groups ug on ug.user_id = p.user_id "+
        "where ug.user_id not in (select user_id from user_groups where group_id in (#{broadcasted_group_ids.join(",")}) ) and ug.group_id=#{self.group_id} and ug.receive_sms = 1 and p.type in(1, 3) and p.carrier is not null")
    emails = []
    puts user_groups.inspect
    user_groups.each do |ug|
      emails << get_sms_address(ug[:number], ug[:carrier]) if not ug[:number].empty?
    end
    puts "^^^^^^^ Inside get distinct sms addresses ^^^^^^^^"
    puts emails.join(",")
    puts "^^^"*60
    emails.join(",")
  end

  # Method to retreive sms addresses.
  def get_sms_addresses
    #user_groups = UserGroup.all(:group_id => self.group_id, :receive_sms => true, UserGroup.user.phone.not => nil,
    #  UserGroup.user.carrier.not => nil)
    user_groups = PhoneNumber.find_by_sql("select p.number, p.carrier from phone_numbers p inner join user_groups ug on ug.user_id = p.user_id "+
        "where ug.group_id=#{self.group_id} and ug.receive_sms = 1 and p.type in(1, 3) and p.carrier is not null")
    emails = []
    user_groups.each do |ug|
      emails << get_sms_address(ug[:number], ug[:carrier]) if not ug[:number].empty?
    end
    puts "^^^^^^^ Inside get sms addresses ^^^^^^^^"
    puts emails.join(",")
    puts "^^^"*60
    emails.join(",")
  end

  # Method to generate the rss text.
  def rss_text
    if self.original_body
      mail = Mail.new(self.original_body)
      # @original_message = mail.body.raw_source
      @original_message = mail.display_message rescue ""

      @original_message.scan(/<img src=\s*['"]\s*cid\s*:\s*([^>]\S*)\s*['"]/i) do |id|
        cid = id[0].strip
        file = self.files.where(:cid => "<#{cid}>").first
        if file
          @original_message = @original_message.gsub(/<img src=\s*['"]\s*cid\s*:\s*#{id[0]}\s*['"]/i, "<img src=\"#{::AWS::S3::S3Object.url_for(file.filename, GlobalBucket)}&pf=#{rand}\"")
        end
      end
      @original_message.scan(/<img (\s*[^>]*) src=\s*['"]\s*cid\s*:\s*([^>]\S*)\s*['"]/i) do |id|
        if id && id.size > 1
          cid = id[1].strip
          file = self.files.where(:cid => "<#{cid}>").first
          if file
            @original_message = @original_message.gsub(/<img #{id[0]} src=\s*['"]\s*cid\s*:\s*#{id[1]}\s*['"]/i, "<img src=\"#{::AWS::S3::S3Object.url_for(file.filename, GlobalBucket)}&pf=#{rand}\"")
          end
        end
      end
      @original_message = @original_message.gsub(/[^[:print:]]/, ' ')
    else
      self.body
    end
  end

  # Method for digest content.
  def digest_content
    if self.original_body
      mail = Mail.new(self.original_body)
    else
      self.body
    end
  end

  # Method to save the topic in a transcation.
  def transaction_save
    self.transaction do
      self.save
    end
  end

  # Method for building the email log for a topic.
  def build_email_log
    if [:web_email, :web_email_sms].include?(self.post_type)
      count = fetch_emails.size || 0
      #      create_message_count("email", count)
      count = (count / 1000.0).ceil if count && count > 0
      count.times do |c|
        emails = fetch_emails.limit(1000).offset(c*1000)
        el = []
        emails.each do |email|
          el << {:email => email.email, :topic_id => self.id, :network_id => self.network.id, :network_name => self.network.name,
            :group_id => self.group_id, :group_name => self.group.name, :status => EmailLog::STATUS.key('Queued'), :created_at => Time.now,
            :updated_at => Time.now, :first_name => email.first_name, :last_name => email.last_name,
            :user_id => email.userid}

        end
        EmailLog.with(safe: true).collection.insert(el)
      end
    end
  end

  # Method to create a campaign.
  def create_campaign
    if [:web_email, :web_email_sms].include?(self.post_type)
      campaign_id = Resque.pop(EMAIL_TRACKING_CODE)
      if campaign_id
        campaign_info = CampaignInfo.find(campaign_id)
        campaign_info.update_attributes(:topic_id => self.id, :published => true) rescue false
      else
        analytics_api = ANALYTICS_CLASS.constantize.new
        Rails.logger.error "Sending request to Litmus for topic_id : #{self.id}"
        html, campaign_id = analytics_api.create_campaign("topic_#{self.id}")
        Rails.logger.error "Got response from Litmus for topic_id : #{self.id} and campaign_id as #{campaign_id}"
        CampaignInfo.create(:tracking_code => html, :campaign_id => campaign_id, :topic_id => self.id, :published => true) if html
      end
    end
  end

  # Method to change the url of the object to display coded anme instead of id.
  def to_param
    coded_subject
  end

  # Method to retieve the opens in a campaign.
  def get_opens
    if self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_opens(self.campaign_info.campaign_id)
    else
      0
    end
  end

  # Method to retieve the geos for a campaign.
  def get_geos
    if self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_geos(self.campaign_info.campaign_id)
    else
      {}
    end
  end

  # Method to retieve the geo cities for a campaign.
  #
  # Parameters :
  #
  # * *region*
  # def get_geo_cities(region)
  #   if self.campaign_info
  #     CampaignCog::get_geo_cities(self.campaign_info.campaign_id, region)
  #   else
  #     {:city => [], :people => []}
  #   end
  # end

  def get_geo_cities(region)
    if false #self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_geo_cities(self.campaign_info.campaign_id)
    else
      {}
    end
  end

  # Method to retieve the message forwards for a campaign.
  def get_forwards
    if self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_forwards(self.campaign_info.campaign_id)
    else
      0
    end
  end

  # Method to retieve the unique opens for a campaign.
  def get_unique_opens
    if self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_unique_opens(self.campaign_info.campaign_id)
    else
      0
    end
  end

  # Method to retieve the message prints for a campaign.
  def get_prints
    if self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_prints(self.campaign_info.campaign_id)
    else
      0
    end
  end

  # Method to retieve the message deletes for a campaign.
  def get_deletes
    if self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_deletes(self.campaign_info.campaign_id)
    else
      0
    end
  end

  # Method to retieve the mail clients for a campaign.
  def get_mail_clients
    if self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_mail_clients(self.campaign_info.campaign_id)
    else
      return {}
    end
  end

  # Method to retieve the devices for a campaign.
  def get_devices
    if self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_devices(self.campaign_info.campaign_id)
    else
      {}
    end
  end

  # Method to retieve the browsers used for a campaign.
  def get_browsers
    if self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_new_browsers(self.campaign_info.campaign_id)
    else
      {}
    end
  end

  # Method to get the engagement report for a campaign.
  def get_engagement_report
    if self.campaign_info
      analytics_api = ANALYTICS_CLASS.constantize.new
      return analytics_api.get_engagements(self.campaign_info.campaign_id)
    else
      {}
    end
  end


  #Method to check if the topic is enabled on rss?
  def show_on_rss?
    show_on_rss
  end

  #Method to check if the topic is enabled on embed?
  def show_on_embed?
    show_on_embed
  end

  # Method to strip html tags of the body of topic
  def text_body
    require 'cgi'
    require 'nokogiri'
    if original_body.present?
      body_text = Mail.new(self.original_body).actual_message
      body_text = self.subject if body_text.blank?
    else
      body_text = body
    end
    body_text = Nokogiri::HTML(CGI.unescapeHTML(body_text)).content.gsub(/\r/, ' ').gsub(/\n/, ' ').gsub('%', ' ').gsub('\\', ' ')
    .gsub(/\u00a0/, ' ').gsub('"', '').split(/[[:space:]]/).delete_if(&:empty?).join(' ') rescue body_text
  end

  def create_cap_message
    alert = Alert.new do |alert|
      alert.sender = self.started_by ? self.started_by.email : self.from_email
      alert.identifier = "#{self.id}"
      alert.status = Alert::STATUS_ACTUAL
      alert.msg_type = Alert::MSG_TYPE_ALERT
      alert.scope = Alert::SCOPE_PUBLIC
      alert.sent = self.created_at

      alert.add_info do |info|
        info.sender_name = self.started_by ? self.started_by.get_full_name : "Admin"
        info.event = "Emergency"
        info.categories << Info::CATEGORY_FIRE
        info.urgency = Info::URGENCY_IMMEDIATE
        info.severity = Info::SEVERITY_SEVERE
        info.certainty = Info::CERTAINTY_OBSERVED
        info.headline = self.subject
        info.description = Hpricot(self.rss_text.gsub("&nbsp;", "")).to_plain_text
        info.contact = "Contact Information"
      end
    end
    return alert.to_xml
  end

  def get_related_topic_ids
    topic_ids = []
    broadcast_group_ids.each do |g|
      topic_ids << Topic.where(:group_id => g, :coded_subject => self.coded_subject).first.id rescue nil if g.to_s != self.group_id.to_s
    end
    topic_ids.compact
  end

  def get_related_topics campus=nil
    topics = []
    broadcast_group_ids = self.broadcast_group_ids
    campus_group_ids = campus.groups.pluck("groups.id") unless campus.blank?
    broadcast_group_ids = broadcast_group_ids.select { |bd| campus_group_ids.include?(bd) } if campus_group_ids && !campus_group_ids.empty?
    broadcast_group_ids.each do |g|
      topics << Topic.where(:group_id => g, :coded_subject => self.coded_subject).first rescue nil if g.to_s != self.group_id.to_s
    end
    topics.compact
  end

  def is_approved?
    state == :active
  end

  def is_pending?
    state == :pending
  end

  def get_open_group_ids
    broadcast_group_ids.collect { |g| g unless Group.find(g).need_review }.compact
  end

  # Method to get all open and approved group ids for a multiple group post.
  def get_open_and_approved_group_ids
    result = []
    broadcast_group_ids.each do |g_id|
      begin
        grp = Group.find(g_id)
        if grp.need_review
          result << g_id if (grp.get_topic(self.coded_subject).is_approved? rescue false)
        else
          result << g_id
        end
      rescue
        next
      end
    end
    result.compact
  end

  # Method to get all open and approved group ids for a multiple group post emailing in with the specific type(:text/:tts) enabled
  def get_email_in_group_ids(type)
    result = []
    broadcast_group_ids.each do |g_id|
      begin
        grp = Group.find(g_id)
        eo = grp.email_option
        options = (type == :text) ? [:premium, :standard_and_premium, :all, :premium_and_tts] : [:tts, :premium_and_tts, :all, :standard_and_tts]
        if grp.need_review
          result << g_id if (grp.get_topic(self.coded_subject).is_approved? && options.include?(eo.send_text) rescue false)
        else
          result << g_id if options.include?(eo.send_text)
        end
      rescue
        next
      end
    end
    result.compact
  end

  def get_sent_group_ids
    sent_group_ids = []
    broadcast_group_ids.reject { |g| g.to_s == self.group_id.to_s }.each do |gid|
      begin
        g = Group.find(gid)
        unless g.set_to_digest?
          if g.need_review
            sent_group_ids << gid if (Topic.where(:group_id => gid, :coded_subject => self.coded_subject)
              .where("updated_at < ?", self.updated_at).first.is_approved? rescue false)
          else
            sent_group_ids << gid
          end
        end
      rescue
        next
      end
    end
    sent_group_ids
  end

  def current_topic_sent_group_ids
    if group.need_review
      # For scheduled and approved, we'll need to find the open and approved groups and decide sent groups based on index of current group.
      if (is_scheduled_post? && is_approved?)
        sent_group_ids = get_open_and_approved_group_ids.split(group_id.to_s).first.collect { |g| g unless Group.find(g).set_to_digest? }.compact
      else
        sent_group_ids = get_sent_group_ids
      end
    else
      sent_group_ids = get_open_and_approved_group_ids.split(group_id.to_s).first.collect { |g| g unless Group.find(g).set_to_digest? }.compact
    end
    sent_group_ids
  end

  def fetch_emails
    group = Group.find(group_id)
    # Find all the group ids for which emails are already sent.
    if group.need_review
      # For scheduled and approved, we'll need to find the open and approved groups and decide sent groups based on index of current group.
      if (is_scheduled_post? && is_approved?)
        sent_group_ids = get_open_and_approved_group_ids.split(group_id.to_s).first.collect { |g| g unless Group.find(g).set_to_digest? }.compact
      else
        sent_group_ids = get_sent_group_ids
      end
    else
      sent_group_ids = get_open_and_approved_group_ids.split(group_id.to_s).first.collect { |g| g unless Group.find(g).set_to_digest? }.compact
    end

    if sent_group_ids.present?
      emails = User.joins(:email_accounts, :user_groups)
      .where(:user_groups => {:membership_type => [1, 5], :group_id => group})
      .where("users.id not in (?)", UserGroup.where(:membership_type => [1, 5], :group_id => sent_group_ids).uniq.pluck(:user_id))
      .order("users.id")
      .select("distinct email_accounts.email, users.first_name, users.last_name, users.id userid")
    else
      emails = User.joins(:email_accounts, :user_groups)
      .where(:user_groups => {:membership_type => [1, 5], :group_id => group})
      .order("users.id")
      .select("distinct email_accounts.email, users.first_name, users.last_name, users.id userid")
    end
    emails = emails.where(:email_accounts => EmailAccount.get_conditions(self.group.network))
    emails
  end

  def fetch_fb_profiles
    network_fb_profiles = self.group.network.get_fb_profiles.where(:can_post => true)
    sent_group_ids = current_topic_sent_group_ids

    sent_fb_profile_ids = SocialNetwork.where(:referal_type => "Group", :social_network_name => "Facebook Profile", :can_post => true).where("referal_id in(?)", sent_group_ids).pluck("facebook_id") + network_fb_profiles.pluck("facebook_id")
    # sent_fb_profile_ids = sent_fb_profile_ids + (started_by.facebook_id ? [started_by.facebook_id] : [])

    fb_profiles = SocialNetwork.where(:referal_type => "Group", :referal_id => group.id, :social_network_name => "Facebook Profile", :can_post => true)
    fb_profiles = fb_profiles.where("facebook_id not in(?)", sent_fb_profile_ids) if sent_fb_profile_ids.present?
    fb_profiles
  end

  def fetch_fb_pages
    network_fb_pages = self.group.network.get_fb_pages
    sent_group_ids = current_topic_sent_group_ids

    sent_fb_page_ids = SocialNetwork.where(:referal_type => "Group", :social_network_name => "Facebook Page").where("referal_id in(?)", sent_group_ids).pluck("facebook_page_id") + network_fb_pages.pluck("facebook_page_id")
    # sent_fb_page_ids = sent_fb_page_ids + (started_by.facebook_page_id ? [started_by.facebook_page_id] : [])

    fb_pages = SocialNetwork.where(:referal_type => "Group", :referal_id => group.id, :social_network_name => "Facebook Page")
    fb_pages = fb_pages.where("facebook_page_id not in(?)", sent_fb_page_ids) if sent_fb_page_ids.present?
    fb_pages
  end

  def topic_medias
    media = []
    media << "Web" if [:web_only, :web_email, :web_sms, :web_email_sms].include?(self.post_type)
    media << "Email" if [:web_email, :web_email_sms].include?(self.post_type)
    media << "TTS" if (self.voice_alert || (!original_body.blank? && [:tts, :premium_and_tts, :all, :standard_and_tts].include?(group.email_option.send_text))) && self.phone_alert.nil?
    media << "TextSMS" if self.smpp_alert || (!original_body.blank? && [:premium, :standard_and_premium, :all, :premium_and_tts].include?(group.email_option.send_text))
    media << "Twitter" if self.publish_to_twitter || (:pending == state && (group.has_twitter_account? || group.network.has_twitter_account?))
    media << "Facebook" if self.publish_to_facebook || is_posted_to_facebook? || (self.publish_to_facebook && :pending == state && (self.group.get_fb_profiles.present? || self.group.network.get_fb_profiles.present?)) || (!original_body.blank? && :pending == state && group.email_option.facebook_post)
    # media << "Facebook Page" if self.publish_to_facebook_page || is_posted_to_facebook_page? || (:pending == state && (self.group.get_fb_pages.present? || self.group.network.get_fb_pages.present?))
    media << "Map" if self.group.map_alert
    media << "AlertManager" if self.push_notification
    media << "API" if self.source == :api
    media << "VoiceAlert" if self.phone_alert
    media
  end

  def comments_count
    self.comments.count
  end

  def get_app_comments(uid)
    user = User.find(uid)
    if self.started_by_id.eql?(uid) || self.group.type.eql?(:open_discussion) || user.is_network_admin?(self.network) || self.group.is_admin?(user)
      self.comments
    else
      self.comments.where(:user_id => uid)
    end
  end

  def text_reply
    SmppAlert.where("topic_id = #{id} and response_id is not null")
  end

  def status_count_for status
    email_logs.where(:status => EmailLog::STATUS.key("#{status}")).size || 0
  end

  def email_logs
    EmailLog.where(:topic_id => self.id)
  end

  def email_logs_count_by_status
    result = EmailLog.collection.aggregate(
      {"$match" => {"topic_id" => self.id}},
      {"$group" => {
          "_id" => "$status",
          "count" => {"$sum" => 1}
        }}
    )
    Hash[result.collect { |h| [EmailLog.print_status(h["_id"]), h["count"]] }] rescue {}
  end

  def voice_status_count_by_status
    message_id = self.phone_alert.nil? ? self.id : self.phone_alert.id
    message_type = self.phone_alert.nil? ? VoiceStatus::MESSAGE_TYPE[:tts] : VoiceStatus::MESSAGE_TYPE[:voice_alert]

    result = VoiceStatus.collection.aggregate(
      {"$match" => {"message_id" => message_id, "message_type" => message_type}},
      {"$group" => {
          "_id" => "$status",
          "count" => {"$sum" => 1}
        }}
    )
    Hash[result.collect { |h| [VoiceStatus.get_displayable_status(h["_id"], Topic::Vendor.db_value(vendor)), h["count"]] }] rescue {}
  end

  def sms_status_count_by_status
    return {} if smpp_alert.nil?
    smpp_alert.sms_status_count_by_status
  end

  def set_dynamic_attributes
    return unless is_scheduled_post?
    self.broadcast_group_ids = self.scheduled_message.group_ids
    group_ids = self.get_open_and_approved_group_ids
    if self.broadcast_group_ids.size > 1
      if (self.group_id.to_s == group_ids.last.to_s)
        self.broadcasted_group_ids = group_ids
        self.email_count = get_email_count(group_ids.join(', '))
      end
    else
      self.email_count = get_email_count(self.group_id)
    end

    if self.scheduled_message.voice_alert
      self.voice_alert = true
      self.caller_id = self.scheduled_message.caller_id
    end
    if self.scheduled_message.alertus_alert
      self.alertus_alert = true
      self.alertus_group = self.scheduled_message.alertus_group
      self.alertus_profile = self.scheduled_message.alertus_profile
    end
    if scheduled_message.facebook
      self.publish_to_facebook = '1'
    end
    if scheduled_message.facebook_page
      self.publish_to_facebook_page = '1'
    end
  end

  def allow_comments
    !self.group.type.eql?(:announcement)
  end

  def send_dynamic_text_tts(users, csv_file_data, header)
    users.each do |user|
      message = self.text_body
      csv_file_data.each do |row|
        case header
        when "email"
          user_match = (row["email"].eql?(user.primary_email))
        when "userID"
          user_match = (row["userID"].eql?(user.get_network_login))
        when "databaseID"
          user_match = (user.external_db_id.eql?("#{self.primary_network.coded_name}-#{row["databaseID"]}"))
        end
        row.each { |key, value| message = message.gsub("[#{key}]", value) } if user_match
      end

      sms_phones = PhoneNumber.connection.execute("select distinct concat(country_code, number) from phone_numbers p where user_id = #{user.id} and type in(1, 3) and p.designation in (#{self.designation})").to_a.flatten
      tts_phones = PhoneNumber.connection.execute("select distinct IF(country_code=1, concat(p.country_code, p.number), concat('011', p.country_code, p.number)) from phone_numbers p where user_id = #{user.id} and type in(2, 3) and p.designation in (#{self.designation})").to_a.flatten

      if sms_phones.present? && self.smpp_alert
        smpp_alert = SmppAlert.new(:message => message, :network_id => self.network.id)
        smpp_alert.save_alert(sms_phones.join(","))
      end

      if tts_phones.present? && self.voice_alert
        if RegroupSystem.first.cdyne?
          CdyneVoice::send_tts(message, tts_phones, self.caller_id, self.id, self.caller_name)
          self.update_column(:vendor, 2)
        else
          cid, error = CallFire::xml_send_to_campaign(message, tts_phones, "[#{self.group.network.coded_name}]#{self.get_subject}", self.caller_id, 1)
          if cid
            Topic.where(:id => self.id).update_all({:campaign_id => cid, :report_status => 0})
          else
            error_message = error ? error.message : "campaign_id is blank"
            Rails.logger.error "#{Time.now}: Error sending Dynamic TTS : #{error_message}"
          end
        end
      end
    end
  end

  def email_user_logs(search=nil, e_type=nil)
    e_type = e_type.present? ? e_type.split(' ') : []
    p e_type
    if !e_type.blank? && !search.blank?
      EmailUserLog.where(:topic_id => self.id, recipient_address: /.*#{search}.*/i).in(event_type: e_type)
    elsif !e_type.blank? && search.blank?
      EmailUserLog.where(:topic_id => self.id).in(event_type: e_type)
    elsif e_type.blank? && !search.blank?
      EmailUserLog.where(:topic_id => self.id, recipient_address: /.*#{search}.*/i)
    else
      EmailUserLog.where(:topic_id => self.id)
    end
  end


  class << self

    # Method to find a topic by coded subject for a network
    #
    # Parameters :
    #
    # * *subj*
    # * *net*
    # def find_by_coded_subject(subj, net)
    #   begin
    #     Topic.joins(:network).where(:coded_subject => subj, :networks => {:coded_name => net}).first ||
    #       TopicAlias.joins(:network).where(:coded_subject => subj, :networks => {:coded_name => net}).first.topic
    #   rescue
    #     nil
    #   end
    # end

    # Method to retreive all topics in chronological order ( newest first ).
    def newest
      order("created_at desc")
    end

    # Method to retreive all topics for a network.
    #
    # Parameters :
    # * *network*
    def in_network(network)
      where(:network_id => network)
    end


    # Method to retreive all topics started by a user.
    #
    # Parameters :
    # * *user*
    def started_by_user(user_id)
      where(:started_by_id => user_id)
    end

    # Class Method to retreive all topics count for networks passed
    #
    # Parameters :
    # * *network*
    def self.count_in_networks(networks)
      query[Topic.network.id] = Array(networks)
      Topic.count(query)
    end

    # Instance Method to retreive all topics count for networks passed
    #
    # Parameters :
    # * *network*
    def count_in_networks(networks)
      query[Topic.network.id] = Array(networks)
      Topic.count(query)
    end

    # Method to retreive all topic in most comment count orders (maximum comments first).
    def most_active
      order("comment_count desc")
    end

    # Method to list the featured topics.
    def featured
      now = DateTime.now
      joins(:feature_topic).where(["feature_topics.priority > 0 and feature_topics.start_date <= ? and feature_topics.end_date > ?", now, now]).sort { |a, b| a.feature.priority <=> b.feature.priority }
    end

    def raw_body(body_text, size=nil)
      ic_ignore = Iconv.new('US-ASCII//IGNORE', 'UTF-8')
      mail_body = body_text
      mail_body = mail_body.gsub("&nbsp;", "").gsub("&nbsp", "") if mail_body
      mail_body = Hpricot(mail_body).to_plain_text
      mail_body = mail_body.gsub(/[\`"{|}~]|\n|\r\n|\n\r|<br\s*\/>|<br\s*>|\[|\]/i, " ")
      size.nil? ? mail_body : mail_body[0..size-1]
    end

    #subject, t_body, group_ids, tts, sms, mail, fb, sender_id = nil, adhoc = false, sms_text = nil, designation

    def create_message(t, test=false)
      Rails.logger.error "Topic Parameters: #{t}"

      message, code, topic_id = "", "", ""
      designation = t[:designation] || "1,2,3,4"
      open_group_ids = t[:group_ids].collect { |g| g unless (Group.find(g).need_review || Group.find(g).set_to_digest?) }.compact
      t[:group_ids].each do |gid|
        group = Group.find(gid)
        ep = group.email_option
        sender = t[:sender_id] == 0 ? nil : t[:sender_id] || group.network.administrators.first.user_id
        user = User.find(sender) rescue nil

        topic = Topic.new(subject: t[:subject],
          body: "<p>#{t[:t_body]}</p>",
          group_id: gid,
          started_by_id: sender,
          broadcast_group_ids: t[:group_ids],
          reply_to: t[:reply_to] || (ep.nil? ? nil : ep.reply_to),
          reply_to_text: t[:reply_to_text] || (ep.nil? ? nil : ep.reply_to_text),
          from_name: t[:from_name] || (ep.nil? ? nil : ep.from_name) || (user.get_full_name rescue nil),
          from_email: t[:from_email] || (ep.nil? ? nil : ep.from_email) || (user.email rescue nil),
          post_type: :web_only,
          designation: designation,
          source: t[:source] || :api,
          call_type: t[:call_type],
          location: t[:latlong],
          show_on_rss: t[:show_on_rss],
          network_id: group.network_id
        )

        if topic.location.present? && topic.group.map_alert
          topic.cad_alert = true
        end

        if t[:cc_emails]
          topic.cc_emails = t[:cc_emails]
        end

        topic.list_mode = group.ad_hoc?

        if t[:mail] && (t[:mail].eql?(true) || t[:mail].eql?("1") || t[:mail].downcase.eql?("yes"))
          topic.post_type = :web_email
          topic.posted_anonymously = t[:posted_anonymously] || false
          if t[:group_ids]
            if t[:group_ids].size > 1
              if (gid == open_group_ids.last)
                topic.broadcasted_group_ids = open_group_ids
                topic.email_count = topic.get_email_count(open_group_ids.join(', '))
              end
            else
              topic.email_count = topic.get_email_count(gid)
            end
          else
            topic.errors.add(:base, "group ID can't be blank.")
          end
        end

        if t[:tts] && (t[:tts].eql?(true) || t[:tts].eql?("1") || t[:tts].downcase.eql?("yes"))
          if group.network.caller_id.present? || t[:caller_id]
            topic.voice_alert = true
            topic.caller_id = t[:caller_id] || group.network.caller_id
            topic.caller_name = t[:caller_name] || group.network.caller_name
          end
        end

        if t[:sms] && (t[:sms].eql?(true) || t[:sms].eql?("1"))
          body_text = t[:sms_text] || Hpricot(t[:t_body]).to_plain_text
          sms_text = body_text.encode("UTF-8", "binary", :invalid => :replace, :undef => :replace, :replace => '')
          sms_text = SmppAlert.remove_unwanted_characters(sms_text)
          topic.smpp_alert = SmppAlert.new({:group_id => gid, :message => sms_text, :user_id => sender, :designation => designation, :group_ids => t[:group_ids]})
        end

        if t[:fb] && (t[:fb].eql?(true) || t[:fb].eql?("1"))
          if group.network.has_fb_account? || group.has_fb_account?
            topic.publish_to_facebook = "1"
          end
        end

        if t[:pn] && (t[:pn].eql?(true) || t[:pn].eql?("1"))
          if group.network.enable_pn?
            topic.push_notification = true
          end
        end

        if topic.errors.blank? && topic.valid?
          if test
            send_test_to_myself(topic)
            break
          else
            topic.transaction_save
            topic_id = topic.id
            message, code = "Your message has been posted successfully!", 200
          end
        else
          Rails.logger.error topic.errors.full_messages
          message, code = topic.errors.full_messages, 422
        end
      end
      message, code = "Your topic has been posted to multiple groups.", 200 if t[:group_ids].size > 1
      message, code = "Test to myself posted successfully.", 200 if test
      return message, code, topic_id
    end

    def send_test_to_myself(topic)
      if topic.post_type == :web_email
        send_test_email(topic)
      end

      if topic.smpp_alert
        phones = PhoneNumber.connection.execute("select distinct distinct concat(country_code, number) from phone_numbers where user_id = #{topic.started_by_id} and type in(1, 3) and designation in (#{topic.designation})").to_a.flatten
        Rails.logger.error "Phone numbers: #{phones}, #{topic.smpp_alert.message}"
        Cdyne::send_test_sms(phones, topic.smpp_alert.message, Cdyne::get_cdyne_key(topic.group.category, topic.network.short_code)) unless phones.empty?
      end

      if topic.voice_alert == true
        phones = PhoneNumber.connection.execute("select distinct distinct concat(country_code, number) from phone_numbers where user_id = #{topic.started_by_id} and country_code = '1' and type in(2, 3) and designation in (#{topic.designation})").to_a.flatten
        Rails.logger.error "Sending Voice Alert to Myself! #{phones}, #{topic.text_body} "
        voice_id, rpt_text = CdyneVoice::get_voice_id(topic.text_body)
        text_to_say = "#{topic.text_body}.~\\PlaySilence(1)~ #{rpt_text}~\\PlaySilence(4)~~\\EndCall()~~\\Label(Amd)~#{topic.text_body}~\\EndCall()~"
        CdyneVoice::send_voice_alert(phones, text_to_say, topic.caller_id, phones.size, "test_myself", 1, 4, voice_id, topic.caller_name) unless phones.empty?
      end

      if topic.push_notification
        #IOS
        device_tokens = UserDevice.where(:user_id => topic.started_by_id, :device_type => 1).pluck(:device_token).uniq
        Rails.logger.error "DEvice tokens Test: #{device_tokens}"
        device_tokens.each { |dt| PushNotification::send_pn("IOS", dt, topic.subject, topic.id) }

        #GCM
        device_tokens = UserDevice.where(:user_id => topic.started_by_id, :device_type => 2).pluck(:device_token).uniq
        Rails.logger.error "DEvice tokens Test: #{device_tokens}"
        PushNotification::send_pn("GCM", device_tokens, topic.subject, topic.id)
      end

    end

    def send_test_email(topic)
      body = topic.body
      body = body += topic.get_footer
      mail = Mail.new
      mail.subject = topic.get_subject
      mail.reply_to = topic.get_reply_to
      mail.from = topic.get_from
      mail.to = EmailAccount.where(:user_id => topic.started_by_id, :receive_email => true).pluck(:email)
      mail.mime_version = '1.0'
      mail['Sender'] = mail['X-Sender'] = topic.get_from

      html_part = Mail::Part.new do
        content_type 'text/html; charset=UTF-8'
        content_transfer_encoding 'Quoted-printable'
        mail_body = [body].pack("M").gsub(/\n/, "\r\n") rescue body
        body mail_body
      end

      mail.part :content_type => "multipart/alternative" do |p|
        p.html_part = html_part
      end

      config = ActionMailer::Base.smtp_settings
      Net::SMTP.start(config[:address], config[:port], config[:domain], config[:user_name], config[:password], config[:authentication]) do |smtp|
        smtp.send_mail(mail.to_s, mail.from.first, mail.destinations) if mail
      end
    end

    def post_xml(subject, body, db_ids, network)
      builder = Nokogiri::XML::Builder.new do |xml|
        xml.topic {
          xml.subject subject
          xml.body body
          xml.mail "1"
          xml.sms "1"
          xml.databaseID db_ids
        }
      end
      resp = HTTParty.post("https://#{SERVER}/api/v2/topics?api_key=#{network.api_key}",
        :body => builder.to_xml,
        :headers => {'Content-Type' => 'application/xml'})
      return resp["response"]
    end

    def get_emails(group_ids, network, users="0")
      User.connection.execute("select distinct e.email from email_accounts e inner join users u "+
          "on u.id=e.user_id inner join user_groups ug "+
          "on ug.user_id = u.id where (ug.group_id in (#{group_ids}) or u.id in (#{users})) and ug.membership_type in (1, 5) and " + EmailAccount.get_conditions(network, str=true, prifix="e")).to_a.flatten
    end

    def get_mul_grs_sms_count(group_ids, designation, users="0")
      PhoneNumber.connection.execute("select count(distinct concat(p.country_code, p.number)) from phone_numbers p inner join user_groups ug on ug.user_id = p.user_id "+
          "where (ug.group_id in (#{group_ids}) or p.user_id in (#{users})) and ug.receive_sms = 1 and p.type in(1, 3) and p.designation in (#{designation})").first[0]
    end

    def get_mul_grs_tts_count(group_ids, designation, users="0")
      PhoneNumber.connection.execute("select count(distinct IF(country_code=1, concat(p.country_code, p.number), concat('011', p.country_code, p.number))) from phone_numbers p inner join user_groups ug on ug.user_id = p.user_id "+
          "where (ug.group_id in (#{group_ids}) or p.user_id in (#{users})) and ug.receive_voice = 1 and p.type in(2, 3)  and p.designation in (#{designation})").first[0]
    end

    def get_chart_data(data_for, user_id, network_id, options={})
      total_email_count = 0
      total_sms_count = 0
      total_voice_count = 0
      total_sent = 0
      user = User.find(user_id)
      network = Network.find(network_id)

      if ["30 Days", "3 Months", "12 Months"].include?(data_for)
        months, format = data_for.eql?("12 Months") ? [11, "b"] : [2, "M"]
        query = data_for.eql?("30 Days") ? "sent_at >= '#{30.days.ago.beginning_of_day}'" : "sent_at >= '#{months.month.ago.beginning_of_month}'"

        if network.is_admin?(user)
          query << " and network_id = #{network_id}"
        elsif user.is_authorize_sender?(network_id)
          query << " and group_id IN (#{user.get_posting_group_ids(network_id).join(",")})"
        else
          return false
        end

        total_messages = MessageCount.where(query)
        total_email_count = total_messages.sum(:email_count)
        total_sms_count = total_messages.sum(:sms_count)
        total_voice_count = total_messages.sum(:voice_count)
        total_sent = total_email_count + total_sms_count + total_voice_count

        if data_for.eql?("30 Days")
          chart_data = {Emails: total_email_count, Texts: total_sms_count, Calls: total_voice_count}
        else
          msg_count = total_messages.group("DATE_FORMAT(sent_at, '%#{format}')").order("YEAR(sent_at),MONTH(sent_at)")

          chart_data = [{name: "Email", data: msg_count.sum(:email_count).to_a},
            {name: "SMS", data: msg_count.sum(:sms_count).to_a},
            {name: "Calls", data: msg_count.sum(:voice_count).to_a}]
        end
        total_email_count = total_messages.sum(:email_count)
        total_sms_count = total_messages.sum(:sms_count)
        total_voice_count = total_messages.sum(:voice_count)
        total_sent = total_email_count + total_sms_count + total_voice_count
      elsif ["Single Post", "SP Pie"].include?(data_for)
        count = Topic.find(options[:topic_id]).message_count rescue nil
        if count
          chart_data = {Emails: count.email_count, Texts: count.sms_count, Calls: count.voice_count}
          total_email_count = chart_data[:Emails]
          total_sms_count = chart_data[:Texts]
          total_voice_count = chart_data[:Calls]
          total_sent = chart_data[:Emails] + chart_data[:Texts] + chart_data[:Calls]
        end
      end
      return {chart_data: chart_data, total_sent: total_sent, total_email_count: total_email_count, total_sms_count: total_sms_count, total_voice_count: total_voice_count}
    end

    def get_summary_chart_data(data_for, user_id, network_id)
      total_email_count = 0
      total_sms_count = 0
      total_voice_count = 0
      total_facebook_count = 0
      total_twitter_count = 0
      user = User.find(user_id)
      network = Network.find(network_id)
      user_roles = user.roles(network)

      if user_roles.network_admin
        group_ids = UserGroup.fetch_user_groups({:conditions => [{:network_id => network.id}]}).pluck("groups.id")
      elsif user_roles.location_admin
        group_ids = user.get_all_campus_admin_campuses_groups(network.id).pluck("groups.id")
      elsif user_roles.group_admin
        group_ids = UserGroup.fetch_user_groups({:user => user, :conditions => ["user_groups.administrator = 1 and user_groups.can_post =1", {:network_id => network.id}]}).pluck("groups.id")
      end

      if ["1 Month", "3 Months", "12 Months"].include?(data_for)
        months, format = data_for.eql?("12 Months") ? [11, "b"] : [2, "M"]
        query = data_for.eql?("30 Days") ? "sent_at >= '#{30.days.ago.beginning_of_day}'" : "sent_at >= '#{months.month.ago.beginning_of_month}'"
        if user_roles.network_admin
          query << " and network_id = #{network_id}"
        elsif user_roles.location_admin || user_roles.group_admin
          query << " and group_id IN (#{group_ids.join(",")})"
        else
          return false
        end
        total_messages = MessageCount.where(query)
        total_email_count = total_messages.sum(:email_count)
        total_sms_count = total_messages.sum(:sms_count)
        total_voice_count = total_messages.sum(:voice_count)
        total_facebook_count = total_messages.sum(:facebook_count)
        total_twitter_count = total_messages.sum(:twitter_count)

        if data_for.eql?("1 Month")
          chart_data = [{name: "Email", data: {:"Total" => total_email_count}},
            {name: "Text", data: {:"Total" => total_sms_count}},
            {name: "Voice", data: {:"Total" => total_voice_count}}
          ]
        else
          msg_count = total_messages.group("DATE_FORMAT(sent_at, '%#{format}')").order("YEAR(sent_at),MONTH(sent_at)")
          all_months = (Date.parse("#{months.month.ago.beginning_of_month}")..Date.today).map { |m| m.strftime('%Y%m') }.uniq
          all_months = data_for.eql?("12 Months") ? all_months.map { |m| Date::ABBR_MONTHNAMES[m[/\d\d$/].to_i] } : all_months.map { |m| Date::MONTHNAMES[m[/\d\d$/].to_i] }
          all_months_counts = []
          all_months.each { |m| all_months_counts << ["#{m}", 0] }
          chart_data = [{name: "Email", data: (all_months_counts + msg_count.sum(:email_count).to_a).inject({}) { |x, y| x[y[0]]=y[1..-1]; x }.map(&:flatten)},
            {name: "Text", data: (all_months_counts + msg_count.sum(:sms_count).to_a).inject({}) { |x, y| x[y[0]]=y[1..-1]; x }.map(&:flatten)},
            {name: "Voice", data: (all_months_counts + msg_count.sum(:voice_count).to_a).inject({}) { |x, y| x[y[0]]=y[1..-1]; x }.map(&:flatten)}]
        end
      end
      return {chart_data: chart_data, total_email_count: total_email_count, total_sms_count: total_sms_count, total_voice_count: total_voice_count, total_facebook_count: total_facebook_count, total_twitter_count: total_twitter_count}
    end

    def get_last_post_statuses(topics)
      all_email_statuses = topics.collect { |t| t.email_logs_count_by_status }
      all_sms_statuses = topics.collect { |t| t.sms_status_count_by_status }
      all_call_statuses = topics.collect { |t| t.phone_alert.nil? ? t.voice_status_count_by_status : t.phone_alert.voice_status_count_by_status }
      email_statuses = all_email_statuses.inject { |memo, el| memo.merge(el) { |k, old_value, new_value| old_value + new_value } }
      sms_statuses = all_sms_statuses.inject { |memo, el| memo.merge(el) { |k, old_value, new_value| old_value + new_value } }
      call_statuses = all_call_statuses.inject { |memo, el| memo.merge(el) { |k, old_value, new_value| old_value + new_value } }
      return {email_statuses: email_statuses, sms_statuses: sms_statuses, call_statuses: call_statuses}
    end

    def get_last_post_common_statuses(topics)
      email_statuses_hash, sms_statuses_hash, call_statuses_hash = {"Delivered" => 0, "Queued" => 0, "Failed" => 0}, {"Delivered" => 0, "Failed" => 0}, {"Delivered" => 0, "Queued" => 0, "Failed" => 0}
      topics.each { |t| t.email_logs_count_by_status.each { |key, val| email_statuses_hash[EmailLog.get_common_displayable_status(key)] += val } }
      topics.each { |t| t.sms_status_count_by_status.each { |key, val| sms_statuses_hash[SmsStatus.get_common_displayable_status(key)] += val } }
      topics.each { |t| t.phone_alert.nil? ? t.voice_status_count_by_status.each { |key, val| call_statuses_hash[VoiceStatus.get_common_displayable_status(key)] += val } : t.phone_alert.voice_status_count_by_status.each { |key, val| call_statuses_hash[VoiceStatus.get_common_displayable_status(key)] += val } }
      return {email_statuses: email_statuses_hash, sms_statuses: sms_statuses_hash, call_statuses: call_statuses_hash}
    end

  end

end
symbolize_enum_values(Topic)
