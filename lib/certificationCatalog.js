// ── The certification catalogue, graded on the server ───────────────────────
//
// Every certification a member can earn, with its questions, options and
// correct answers. Until this file existed, all of it lived in
// certifications.html: the page held the answer key, scored the quiz itself
// and told POST /api/certifications/award "passed: true, score: 90". The
// route believed it, and accepted any cert_id, so a subscriber could post
// cert_id "a1", "a2", "a3" … with passed: true and be paid 100 BFC for each,
// without limit (the launch audit, 2026-10-19, item #3).
//
// Now the page asks GET /api/certifications/catalog for the questions, which
// it serves WITHOUT the answers (publicCertificationCatalog), and sends back
// only the chosen options. The route looks the cert_id up here
// (findCertification) and grades the answers here (gradeCertification). A
// cert_id that is not in this list cannot be earned at all.
//
// THE EARNING BOUND. The credit is 100 BFC, paid once per certification on its
// first server-graded pass while subscribed. So the most BFC any one account
// can ever earn from certifications is CERTIFICATIONS.length × 100: 12 × 100
// = 1,200 BFC today. Adding a certification raises that bound by 100.
//
// The 12 certifications and 120 questions were moved here unchanged from
// certifications.html as it stood at a8b45fc: same ids, wording, option
// order and answers. The pass mark is the page's own 80%.
//
// No model call, no network, no database.

var CERTIFICATION_PASS_MARK = 80;

var CERTIFICATIONS = [
  {
    id: "sales-1",
    category: "Sales",
    name: "Sales Fundamentals",
    desc: "Master the core concepts of selling: funnels, qualification, objection handling, and conversion.",
    difficulty: "Beginner",
    questions: [
      { q: "What is the primary goal of a sales funnel?",
        opts: ["Increase marketing spend","Guide prospects through buying stages","Generate press coverage","Build social media followers"],
        ans: 1 },
      { q: "Which metric best measures sales team performance?",
        opts: ["Website traffic","Conversion rate","Number of emails sent","Social media likes"],
        ans: 1 },
      { q: "\"Cold calling\" means contacting prospects…",
        opts: ["After a previous sale","With no prior relationship","Who are already customers","Through referrals only"],
        ans: 1 },
      { q: "AIDA stands for…",
        opts: ["Awareness, Interest, Decision, Action","Attention, Interest, Desire, Action","Analysis, Insight, Data, Assessment","Acquire, Influence, Direct, Achieve"],
        ans: 1 },
      { q: "A \"pain point\" in sales is best described as…",
        opts: ["A difficult customer","A competitor's advantage","A problem the customer needs solved","A failed sales call"],
        ans: 2 },
      { q: "The SPIN selling technique stands for…",
        opts: ["Situation, Problem, Implication, Need-Payoff","Sales, Profit, Interest, Numbers","Strategy, Pipeline, Initiative, Net-revenue","Success, Planning, Information, Nurturing"],
        ans: 0 },
      { q: "\"Social proof\" in sales refers to…",
        opts: ["Social media advertising","Evidence that others have benefited from your product","A public relations campaign","Word-of-mouth marketing only"],
        ans: 1 },
      { q: "When handling a price objection, the best first response is to…",
        opts: ["Immediately discount the price","End the conversation","Reframe the value and demonstrate ROI","Blame the product"],
        ans: 2 },
      { q: "B2B stands for…",
        opts: ["Business to Business","Buy to Buy","Brand to Brand","Build to Buy"],
        ans: 0 },
      { q: "A \"qualified lead\" is a prospect who has…",
        opts: ["A large social following","Budget, authority, need, and timeline to buy","Visited your website","Responded to an email"],
        ans: 1 }
    ]
  },
  {
    id: "sales-2",
    category: "Sales",
    name: "Advanced Sales Strategy",
    desc: "Go deep on pipeline management, account-based selling, CRM strategy, and advanced closing techniques.",
    difficulty: "Intermediate",
    questions: [
      { q: "\"Pipeline velocity\" measures…",
        opts: ["Speed of email responses","Rate at which deals move through the pipeline","Speed of order fulfillment","Sales team communication speed"],
        ans: 1 },
      { q: "The \"challenger sale\" methodology focuses on…",
        opts: ["Discounting aggressively","Only responding to inbound leads","Teaching prospects something new that disrupts their thinking","Following up daily"],
        ans: 2 },
      { q: "Account-based selling (ABS) is most effective for…",
        opts: ["B2C retail","High-value, complex B2B deals","Social media campaigns","Email newsletters"],
        ans: 1 },
      { q: "\"Sandbagging\" in sales means…",
        opts: ["Overcommitting to targets","Deliberately underestimating a deal to exceed quota","Adding unnecessary product features","Removing old leads from CRM"],
        ans: 1 },
      { q: "A win/loss analysis helps you…",
        opts: ["Track email open rates","Count competitors","Understand why deals are won or lost to improve strategy","Manage inventory"],
        ans: 2 },
      { q: "What is \"upselling\"?",
        opts: ["Raising the price of existing products","Encouraging a customer to purchase a higher-tier product","Selling only to existing customers","Offering discounts to close deals"],
        ans: 1 },
      { q: "Which CRM feature is most critical for revenue forecasting?",
        opts: ["Contact storage","Pipeline stage tracking with deal probability","Email templates","Calendar syncing"],
        ans: 1 },
      { q: "In the MEDDIC framework, \"Champion\" refers to…",
        opts: ["The largest deal closed","An internal advocate who promotes your solution","The sales manager","The top-performing rep"],
        ans: 1 },
      { q: "Churn rate measures…",
        opts: ["The speed of new customer acquisition","The rate at which customers stop buying","Profit margins","Market share"],
        ans: 1 },
      { q: "What does \"cross-selling\" mean?",
        opts: ["Selling to competitors","Offering a complementary product to an existing customer","Increasing a customer's plan tier","Selling in a new geography"],
        ans: 1 }
    ]
  },
  {
    id: "sales-3",
    category: "Sales",
    name: "Revenue Optimization",
    desc: "Learn LTV, churn reduction, pricing strategy, upsell architecture, and SaaS growth frameworks.",
    difficulty: "Advanced",
    questions: [
      { q: "Customer Lifetime Value (CLV) is calculated as…",
        opts: ["Revenue × margins","Average purchase value × purchase frequency × customer lifespan","Leads × conversion rate","MRR × 12"],
        ans: 1 },
      { q: "Net Revenue Retention (NRR) above 100% indicates…",
        opts: ["Negative churn — expansion revenue exceeds lost revenue","Customer satisfaction only","New customer growth","High advertising spend"],
        ans: 0 },
      { q: "Product-led growth (PLG) means…",
        opts: ["Advertising-driven acquisition","The product itself drives user acquisition and expansion","Large enterprise sales teams","PR campaigns"],
        ans: 1 },
      { q: "Which pricing strategy best extracts maximum willingness to pay?",
        opts: ["Cost-plus pricing","Penetration pricing","Value-based pricing","Competitive pricing"],
        ans: 2 },
      { q: "Annual Recurring Revenue (ARR) is most relevant to…",
        opts: ["E-commerce stores","SaaS and subscription businesses","Physical retail","One-time service providers"],
        ans: 1 },
      { q: "A \"land and expand\" strategy means…",
        opts: ["Starting with a small deal and growing the account over time","Geographic market expansion","Acquiring competitors","Product line extension"],
        ans: 0 },
      { q: "The Rule of 40 in SaaS states that…",
        opts: ["40% of revenue should be profit","Growth rate % + profit margin % should equal or exceed 40","40 customers is the break-even point","40 days is the ideal sales cycle"],
        ans: 1 },
      { q: "\"Revenue leakage\" refers to…",
        opts: ["Refunds only","Money lost due to process inefficiencies, billing errors, or missed upsells","Marketing overspend","Pricing errors only"],
        ans: 1 },
      { q: "\"Price elasticity\" measures…",
        opts: ["Profit margins","How demand changes in response to price changes","Inventory flexibility","Team capacity"],
        ans: 1 },
      { q: "Which has the highest impact on revenue per employee?",
        opts: ["Hiring more salespeople","Automation and process optimization","Reducing prices","Increasing advertising"],
        ans: 1 }
    ]
  },
  {
    id: "marketing-1",
    category: "Marketing",
    name: "Content Marketing Foundations",
    desc: "Build a content strategy from scratch — calendars, SEO basics, CTAs, and repurposing workflows.",
    difficulty: "Beginner",
    questions: [
      { q: "What is the purpose of a content calendar?",
        opts: ["Tracking ad spend","Organizing and scheduling content in advance","Measuring website traffic","Managing social followers"],
        ans: 1 },
      { q: "\"SEO\" stands for…",
        opts: ["Sales Excellence Operations","Search Engine Optimization","Social Engagement Outreach","System Enhancement Output"],
        ans: 1 },
      { q: "Which content format typically generates the most organic reach?",
        opts: ["Stock photos","Short-form video","Long PDFs","Text-only posts"],
        ans: 1 },
      { q: "A \"content pillar\" is…",
        opts: ["A one-time blog post","A social media ad","A core topic that spawns multiple pieces of content","A website header image"],
        ans: 2 },
      { q: "What is a \"call to action\" (CTA)?",
        opts: ["A customer complaint","A prompt directing the audience to take a specific next step","A sales script","An email subject line"],
        ans: 1 },
      { q: "Which metric measures how many visitors completed a desired action on a landing page?",
        opts: ["Bounce rate","Conversion rate","Session duration","Impressions"],
        ans: 1 },
      { q: "User-generated content (UGC) is valuable primarily because…",
        opts: ["It is free to produce","It provides authentic social proof and trust","It always ranks better in search","It requires no editing"],
        ans: 1 },
      { q: "Content repurposing means…",
        opts: ["Deleting old content","Adapting one piece of content into multiple formats","Reposting competitors' content","Republishing content unchanged"],
        ans: 1 },
      { q: "An \"editorial calendar\" maps…",
        opts: ["Ad results to budgets","Content topics to publishing dates and channels","A list of content writers","Email tool schedules"],
        ans: 1 },
      { q: "Which funnel stage does brand awareness content primarily serve?",
        opts: ["Decision","Retention","Advocacy","Top of funnel — Awareness"],
        ans: 3 }
    ]
  },
  {
    id: "marketing-2",
    category: "Marketing",
    name: "Digital Marketing Mastery",
    desc: "Retargeting, A/B testing, email optimization, influencer partnerships, and paid media fundamentals.",
    difficulty: "Intermediate",
    questions: [
      { q: "\"Retargeting\" in digital advertising means…",
        opts: ["Emailing inactive subscribers","Showing ads to people who previously visited your website","Re-posting old content","Following up on lost leads"],
        ans: 1 },
      { q: "\"A/B testing\" in marketing involves…",
        opts: ["Testing two different budgets","Testing two versions of content to find which performs better","Comparing two competitors","Two reviewers evaluating the same ad"],
        ans: 1 },
      { q: "CPM in digital advertising stands for…",
        opts: ["Cost Per Month","Cost Per Mile","Cost Per Thousand impressions","Cost Per Message"],
        ans: 2 },
      { q: "Email open rate is best improved by…",
        opts: ["Sending more emails","Optimizing subject lines and send timing","Adding more images","Increasing email length"],
        ans: 1 },
      { q: "\"Influencer marketing\" means…",
        opts: ["Cold outreach to investors","Partnering with content creators to reach their audience","Influencing search algorithms","Advertising on news sites"],
        ans: 1 },
      { q: "Google Analytics primarily tracks…",
        opts: ["Social media engagement","Email performance","Website visitor behavior and traffic sources","Ad creative performance"],
        ans: 2 },
      { q: "\"Organic reach\" refers to…",
        opts: ["Revenue from content","Audience reached without paid promotion","Followers gained through ads","Natural language in copy"],
        ans: 1 },
      { q: "A \"lead magnet\" is…",
        opts: ["A viral video","A high-end product","A free offer designed to attract email subscribers","A pop-up ad"],
        ans: 2 },
      { q: "\"CTR\" stands for…",
        opts: ["Content Traffic Rate","Click-Through Rate","Customer Transaction Rate","Creative Test Ratio"],
        ans: 1 },
      { q: "Which platform is generally most effective for B2B digital marketing?",
        opts: ["TikTok","Pinterest","LinkedIn","Snapchat"],
        ans: 2 }
    ]
  },
  {
    id: "marketing-3",
    category: "Marketing",
    name: "Marketing Analytics Pro",
    desc: "Attribution modeling, CAC, cohort analysis, LTV:CAC, and multi-touch attribution.",
    difficulty: "Advanced",
    questions: [
      { q: "\"Attribution modeling\" in marketing means…",
        opts: ["Designing ad creatives","Assigning credit to marketing touchpoints that led to a conversion","Tracking competitor ads","Building audience segments"],
        ans: 1 },
      { q: "Customer Acquisition Cost (CAC) is calculated as…",
        opts: ["Total revenue / total customers","Total sales + marketing costs / new customers acquired","Total traffic / conversions","Leads × close rate"],
        ans: 1 },
      { q: "\"Cohort analysis\" analyzes…",
        opts: ["Team performance reviews","Groups of users who share a characteristic, tracked over time","Email segmentation","Social media analytics"],
        ans: 1 },
      { q: "An LTV:CAC ratio of 3:1 means…",
        opts: ["The business is losing money","The business generates 3x the customer lifetime value vs. acquisition cost","Revenue is flat","Marketing is underperforming"],
        ans: 1 },
      { q: "\"Multi-touch attribution\" solves…",
        opts: ["Email spam issues","The challenge of crediting multiple channels that contributed to a sale","Slow website loading","Low ad quality scores"],
        ans: 1 },
      { q: "\"Funnel drop-off rate\" measures…",
        opts: ["Sales team attrition","Percentage of users who leave at each funnel stage","Email unsubscribes","Ad impression decline"],
        ans: 1 },
      { q: "\"Statistical significance\" in marketing tests means…",
        opts: ["A large sample size","Confidence that a test result is not due to random chance","Positive ROI","A 50%+ conversion rate"],
        ans: 1 },
      { q: "\"Dark social\" traffic refers to…",
        opts: ["Anonymous website visitors","Private shares via messaging apps or email that don't show in analytics","Hacked accounts","Bot traffic"],
        ans: 1 },
      { q: "\"Share of Voice\" (SOV) measures…",
        opts: ["Revenue share","Brand presence relative to competitors in a market","Podcast listener share","Social media follower percentage"],
        ans: 1 },
      { q: "Marketing Mix Modeling (MMM) helps businesses…",
        opts: ["Design brand logos","Understand the ROI of each marketing channel to optimize spend","Hire marketing staff","Write better ad copy"],
        ans: 1 }
    ]
  },
  {
    id: "analytics-1",
    category: "Analytics",
    name: "Data Analysis Basics",
    desc: "Learn KPIs, dashboards, pivot tables, data integrity, and core statistical concepts.",
    difficulty: "Beginner",
    questions: [
      { q: "KPI stands for…",
        opts: ["Key Product Indicator","Key Performance Indicator","Key Profit Index","Known Productivity Item"],
        ans: 1 },
      { q: "A \"data dashboard\" is primarily used to…",
        opts: ["Store raw data","Visualize key metrics in real time","Write narrative reports","Collect customer data"],
        ans: 1 },
      { q: "\"Data normalization\" means…",
        opts: ["Deleting unusual values","Organizing data to reduce redundancy and improve consistency","Making all numbers equal","Averaging data sets"],
        ans: 1 },
      { q: "An \"outlier\" in data analysis is…",
        opts: ["A hidden data source","A data point significantly different from the rest","The most common value","A missing value"],
        ans: 1 },
      { q: "Mean, median, and mode are all measures of…",
        opts: ["Variance","Data distribution","Central tendency","Growth rate"],
        ans: 2 },
      { q: "What is a \"pivot table\"?",
        opts: ["A database table","A data summarization tool that reorganizes and aggregates data","A business strategy","A type of chart"],
        ans: 1 },
      { q: "Data visualization primarily helps by…",
        opts: ["Hiding sensitive data","Making complex data easier to understand and communicate","Automating reporting","Increasing data accuracy"],
        ans: 1 },
      { q: "CSV stands for…",
        opts: ["Comma-Separated Values","Customized System Variables","Client Software Version","Content Storage View"],
        ans: 0 },
      { q: "A \"trend line\" in data analysis shows…",
        opts: ["Current sales figures","The general direction of data over time","Customer geographic locations","Expense totals"],
        ans: 1 },
      { q: "\"Data integrity\" means…",
        opts: ["Encrypting all data","The accuracy and consistency of data throughout its lifecycle","Large-scale data storage","Fast data retrieval"],
        ans: 1 }
    ]
  },
  {
    id: "analytics-2",
    category: "Analytics",
    name: "Business Intelligence",
    desc: "Deep-dive into OLAP, ETL, data warehousing, star schemas, and BI tooling.",
    difficulty: "Intermediate",
    questions: [
      { q: "OLAP stands for…",
        opts: ["Online Language Analytics Platform","Online Analytical Processing","Output Layer Analysis Protocol","Organizational Learning and Performance"],
        ans: 1 },
      { q: "ETL stands for…",
        opts: ["Email, Transfer, Launch","Extract, Transform, Load","Evaluate, Test, Launch","Enterprise Task Log"],
        ans: 1 },
      { q: "A \"data warehouse\" is…",
        opts: ["A place to store physical hardware","A central repository of integrated data from multiple sources","A cloud backup system","A database management tool"],
        ans: 1 },
      { q: "Business Intelligence (BI) primarily helps organizations…",
        opts: ["Build websites","Hire better employees","Make data-driven decisions","Reduce headcount"],
        ans: 2 },
      { q: "A \"star schema\" in database design consists of…",
        opts: ["A 5-star rating system","A central fact table surrounded by dimension tables","A star-shaped org chart","A circular data model"],
        ans: 1 },
      { q: "\"Real-time analytics\" refers to…",
        opts: ["Analyzing data from the last year","Processing and analyzing data as it is generated","Updating dashboards monthly","Annual reporting cycles"],
        ans: 1 },
      { q: "\"Data governance\" is…",
        opts: ["Government data regulations","The framework ensuring data quality, security, and proper use","Encrypting databases","Auditing financial records only"],
        ans: 1 },
      { q: "Which tool category is most commonly used for BI dashboards?",
        opts: ["Word processing software","Visualization tools like Tableau or Power BI","Image editing software","Messaging apps"],
        ans: 1 },
      { q: "\"Drill-down\" in BI means…",
        opts: ["Deleting detailed data","Exploring more detailed layers within aggregated data","Exporting reports","Combining disparate data sources"],
        ans: 1 },
      { q: "A \"data lake\" differs from a data warehouse in that it…",
        opts: ["Stores only structured data","Is smaller in capacity","Stores raw, unprocessed data in native format","Only holds financial data"],
        ans: 2 }
    ]
  },
  {
    id: "analytics-3",
    category: "Analytics",
    name: "Predictive Analytics",
    desc: "Machine learning basics, regression analysis, classification models, and churn prediction.",
    difficulty: "Advanced",
    questions: [
      { q: "Predictive analytics uses…",
        opts: ["Current news headlines","Historical data and statistical models to forecast future outcomes","Customer interviews only","Real-time social data only"],
        ans: 1 },
      { q: "\"Machine learning\" in analytics means…",
        opts: ["Hardware optimization","Algorithms that learn from data to improve predictions over time","Manual data entry","Employee training programs"],
        ans: 1 },
      { q: "\"Regression analysis\" is a method for…",
        opts: ["Going back to older methods","Understanding relationships between variables","Analyzing declining metrics","Data rollback procedures"],
        ans: 1 },
      { q: "\"Overfitting\" in a predictive model means…",
        opts: ["The model performs too well on new data","The model performs well on training data but poorly on new data","The dataset is too large","Predictions are too conservative"],
        ans: 1 },
      { q: "A \"classification model\" is one that…",
        opts: ["Categorizes data points into distinct groups","Predicts continuous numeric values","Sorts records alphabetically","Cleans messy data"],
        ans: 0 },
      { q: "\"Training data\" in machine learning is…",
        opts: ["Data used to improve employee skills","Historical data used to build and teach a predictive model","Real-time streaming data","Data collected about competitors"],
        ans: 1 },
      { q: "\"Churn prediction\" enables a business to…",
        opts: ["Track competitor activity","Identify customers likely to cancel before they do, enabling proactive retention","Forecast sales seasonality","Optimize email send timing"],
        ans: 1 },
      { q: "A \"confusion matrix\" is used to measure…",
        opts: ["User confusion on a website","The accuracy and error types of a classification model","Employee performance","Customer satisfaction"],
        ans: 1 },
      { q: "\"Feature engineering\" means…",
        opts: ["Hiring data engineers","Creating new variables from raw data to improve model performance","Hardware setup","Software feature planning"],
        ans: 1 },
      { q: "What is the purpose of a \"validation set\" in model training?",
        opts: ["To store backup data","To evaluate model performance on unseen data during training","To collect new customer data","To validate employee credentials"],
        ans: 1 }
    ]
  },
  {
    id: "leadership-1",
    category: "Leadership",
    name: "Leadership Essentials",
    desc: "Servant leadership, emotional intelligence, delegation, active listening, and SMART goals.",
    difficulty: "Beginner",
    questions: [
      { q: "\"Servant leadership\" is a style focused on…",
        opts: ["Following orders from above","Serving and empowering the team","Delegating all work","Strict top-down management"],
        ans: 1 },
      { q: "Emotional intelligence (EQ) in leadership refers to…",
        opts: ["Technical knowledge","Understanding and managing your own emotions and others'","Analytical skills","Decision-making speed"],
        ans: 1 },
      { q: "\"Psychological safety\" in a team means…",
        opts: ["Physical safety protocols","A culture where members feel safe speaking up, taking risks, and making mistakes","Employee health insurance","Safety training programs"],
        ans: 1 },
      { q: "\"Delegation\" in leadership means…",
        opts: ["Micromanaging every task","Assigning tasks and authority to others while remaining accountable","Refusing to share work","Reducing team size"],
        ans: 1 },
      { q: "Active listening means…",
        opts: ["Preparing your response while others talk","Fully concentrating, understanding, and responding thoughtfully","Taking extensive notes","Speaking more than listening"],
        ans: 1 },
      { q: "SMART goals stand for…",
        opts: ["Simple, Measurable, Agile, Realistic, Timely","Specific, Measurable, Achievable, Relevant, Time-bound","Strategic, Mindful, Attainable, Rapid, Tracked","Systematic, Managed, Actionable, Reviewed, Targeted"],
        ans: 1 },
      { q: "A \"1-on-1\" meeting is primarily used for…",
        opts: ["Annual performance reviews only","Regular check-ins for coaching and support between leader and team member","Company-wide announcements","Team retrospectives only"],
        ans: 1 },
      { q: "Transformational leadership focuses on…",
        opts: ["Maintaining the status quo","Transactional rewards only","Inspiring and motivating teams toward a compelling vision","Process compliance above all"],
        ans: 2 },
      { q: "\"Conflict resolution\" in leadership means…",
        opts: ["Avoiding all disagreements","Addressing and resolving disputes constructively","Disciplining employees","Escalating all issues upward"],
        ans: 1 },
      { q: "\"Leading by example\" means…",
        opts: ["Telling employees exactly what to do","Modeling the behavior and values you expect from your team","Avoiding responsibility","Creating policies and guidelines"],
        ans: 1 }
    ]
  },
  {
    id: "leadership-2",
    category: "Leadership",
    name: "Executive Decision Making",
    desc: "Decision fatigue, Pareto principle, scenario planning, SWOT analysis, and cognitive bias.",
    difficulty: "Intermediate",
    questions: [
      { q: "\"Decision fatigue\" refers to…",
        opts: ["Exhaustion from processing too much data","The decline in decision quality after making many decisions","Analysis paralysis only","Board meeting exhaustion"],
        ans: 1 },
      { q: "The Pareto Principle (80/20 rule) states that…",
        opts: ["80% of effort produces 20% of results","80% of results come from 20% of causes","20% of employees do 80% of work","80% of customers are unprofitable"],
        ans: 1 },
      { q: "\"Scenario planning\" involves…",
        opts: ["Writing business case studies","Developing strategies for multiple possible future situations","Reviewing past decisions","Forecasting quarterly earnings only"],
        ans: 1 },
      { q: "\"First principles thinking\" means…",
        opts: ["Following industry best practices","Breaking problems down to fundamental truths and reasoning upward","Using proven templates","Following senior leadership guidance"],
        ans: 1 },
      { q: "\"Opportunity cost\" is…",
        opts: ["The cost of missed marketing campaigns","The value of the next-best alternative forgone when making a decision","Project over-budget amounts","Employee turnover costs"],
        ans: 1 },
      { q: "A SWOT analysis evaluates…",
        opts: ["Sales, Work, Operations, Team","Strengths, Weaknesses, Opportunities, Threats","Strategy, Workforce, Objectives, Tactics","Systems, Workflow, Output, Timeline"],
        ans: 1 },
      { q: "Why does distinguishing reversible vs. irreversible decisions matter?",
        opts: ["Irreversible decisions require more caution and deeper analysis","All decisions should be reversible","Reversible decisions are more important","Speed always matters more than reversibility"],
        ans: 0 },
      { q: "\"Stakeholder analysis\" involves…",
        opts: ["Tracking stock performance","Identifying parties affected by decisions and understanding their interests","Investor relations management","Employee satisfaction surveys only"],
        ans: 1 },
      { q: "\"Cognitive bias\" in decision-making refers to…",
        opts: ["Rational analytical thinking","Systematic deviations from rationality that affect judgments","Slow, cautious decision-making","Data overload"],
        ans: 1 },
      { q: "The \"pre-mortem\" technique involves…",
        opts: ["Reviewing past project failures","Imagining a project has failed and identifying why before it starts","Conducting exit interviews","Board-level risk assessments"],
        ans: 1 }
    ]
  },
  {
    id: "leadership-3",
    category: "Leadership",
    name: "Strategic Management",
    desc: "Competitive moats, Porter's Five Forces, blue ocean strategy, and platform strategy.",
    difficulty: "Advanced",
    questions: [
      { q: "A \"competitive moat\" is…",
        opts: ["A marketing strategy","A sustainable competitive advantage that protects a business from rivals","A financial reserve fund","A patent portfolio only"],
        ans: 1 },
      { q: "Porter's Five Forces model analyzes…",
        opts: ["Five leadership styles","Five forces that shape industry competition and profitability","Five marketing channels","Five financial metrics"],
        ans: 1 },
      { q: "\"Blue ocean strategy\" means…",
        opts: ["Competing aggressively in existing markets","Creating uncontested new market space with no competition","Entering international markets","Optimizing existing products"],
        ans: 1 },
      { q: "\"Organizational agility\" refers to…",
        opts: ["Employee physical fitness","An organization's ability to rapidly adapt to market changes","Remote work capability","Fast hiring processes"],
        ans: 1 },
      { q: "\"Economies of scale\" mean…",
        opts: ["Smaller businesses are always more efficient","Cost per unit decreases as production volume increases","Revenue always grows faster than costs","Market share automatically increases"],
        ans: 1 },
      { q: "A \"core competency\" is…",
        opts: ["A required technical job skill","A unique capability that gives a business a competitive advantage","A standard industry practice","A team's combined skills list"],
        ans: 1 },
      { q: "\"Vertical integration\" means…",
        opts: ["Acquiring horizontal competitors","Expanding into supply chain stages upstream or downstream","Hiring senior executives","Merging with a direct competitor"],
        ans: 1 },
      { q: "\"Market penetration\" as a growth strategy focuses on…",
        opts: ["Entering new markets","Increasing share in existing markets with existing products","Developing new products","Acquiring direct competitors"],
        ans: 1 },
      { q: "A \"balanced scorecard\" is…",
        opts: ["An employee performance review tool","A strategic framework measuring performance across financial, customer, internal process, and learning dimensions","A budget management system","A project management methodology"],
        ans: 1 },
      { q: "\"Platform strategy\" creates value by…",
        opts: ["Building proprietary software","Facilitating interactions and transactions between two or more user groups","Expanding product lines","Increasing prices across segments"],
        ans: 1 }
    ]
  }
];

/* Frozen all the way down, so nothing that requires this module can change a
   question or an answer for the rest of the process. */
function deepFreeze(value) {
  if (value && typeof value === "object") {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}
deepFreeze(CERTIFICATIONS);

// The catalogue entry for an id, or null. An exact match: no trimming, no
// lowercasing, so "Sales-1" is not "sales-1".
function findCertification(certId, catalogue) {
  var list = catalogue || CERTIFICATIONS;
  for (var i = 0; i < list.length; i++) {
    if (list[i].id === certId) return list[i];
  }
  return null;
}

/* What the page may see: everything but the answers. Built field by field
   rather than by deleting `ans` from a copy, so a field added to a question
   later is not served until someone adds it here on purpose. */
function publicCertification(cert) {
  return {
    id: cert.id,
    category: cert.category,
    name: cert.name,
    desc: cert.desc,
    difficulty: cert.difficulty,
    pass_mark: CERTIFICATION_PASS_MARK,
    question_count: cert.questions.length,
    questions: cert.questions.map(function (q) {
      return { q: q.q, opts: q.opts.slice() };
    })
  };
}

function publicCertificationCatalog(catalogue) {
  return (catalogue || CERTIFICATIONS).map(publicCertification);
}

/* Grades one submission. `answers` must be an array with one entry per
   question, in order: the index of the chosen option, or null for a skipped
   question, which counts as wrong. Anything else is refused rather than
   guessed at, so a malformed submission is never recorded as a fail.

   Returns { ok: true, correct, total, score, passed } or { ok: false, error }.
   score is a whole percentage, rounded the way the page always rounded it,
   and passed is score >= CERTIFICATION_PASS_MARK. */
function gradeCertification(cert, answers) {
  var total = cert.questions.length;

  if (!Array.isArray(answers)) {
    return { ok: false, error: "answers must be a list with one entry per question (" + total + " for " + cert.id + ")." };
  }
  if (answers.length !== total) {
    return { ok: false, error: "answers has " + answers.length + " entries, but " + cert.id + " has " + total + " questions." };
  }

  var correct = 0;
  for (var i = 0; i < total; i++) {
    var given = answers[i];
    var optionCount = cert.questions[i].opts.length;
    if (given === null) continue;
    if (!Number.isInteger(given) || given < 0 || given >= optionCount) {
      return { ok: false, error: "answers[" + i + "] must be an option number from 0 to " + (optionCount - 1) + ", or null for a skipped question." };
    }
    if (given === cert.questions[i].ans) correct++;
  }

  var score = Math.round((correct / total) * 100);
  return { ok: true, correct: correct, total: total, score: score, passed: score >= CERTIFICATION_PASS_MARK };
}

module.exports = {
  CERTIFICATIONS,
  CERTIFICATION_PASS_MARK,
  findCertification,
  publicCertification,
  publicCertificationCatalog,
  gradeCertification
};
