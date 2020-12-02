package lib

func GroupDescription() map[string]string {
	groups := make(map[string]string)
	groups["FP-FBA Role: Active"] = "Active users have all granted privileges to them. All actions are visible within Forcepoint UEBA."
	groups["FP-FBA Role: Inactive"] = "Inactive users cannot login, their history is visible within Forcepoint UEBA and indicated with inactive label."
	groups["FP-FBA Role: Restricted User"] = "Restricted User. Can access the Explore page as well as the Configuration, Guide, and Profile pages under the Settings menu"
	groups["FP-FBA Role: Shielded User"] = "Can access Analytic Dashboard, Review Dashboard, Entity Timeline, Explore page as well as the Configuration and Guide, but is shielded from certain raw fields"
	groups["FP-FBA Role: Risk-Adaptive-Protection User"] = "Risk-Adaptive-Protection User. Has access to dashboard, entities page, entity profile, jobs, exports, and explore page."
	groups["FP-FBA Role: Risk-Adaptive-Protection Admin"] = "Risk-Adaptive-Protection Admin. Has access to user management pages."
	groups["FP-FBA Role: user"] = "Basic use case: access the Explore and Entities pages as well as the Configuration, Guide, and Profile pages under the Settings menu"
	groups["FP-FBA Role: Analyst"] = "Expanded Forcepoint UEBA user: access the Review Dashboard page as well as the Job Status and Profile pages under the Settings menu."
	groups["FP-FBA Role: Behaviors Analyst"] = "Expanded Forcepoint UEBA user: access the Behaviors page, Analytic Dashboard, and the Job Status and Profile pages under the Settings menu."
	groups["FP-FBA Role: Exporter"] = "File exporting: access functionality for exporting events"
	groups["FP-FBA Role: Reviewer"] = "Can access and use the Review Dashboard"
	groups["FP-FBA Role: Restricted reviewer"] = "Can access and use the Review Dashboard, with the restrictions on available Actions in the Event Viewer and limited to only seeing Features that are in the user Saved Searches"
	groups["FP-FBA Role: Modeler"] = "Behavioral Modeling: create, update, and delete Models and Features (need Behaviors Analyst Role to read Behaviors page)"
	groups["FP-FBA Role: Admin"] = "User management only: manage users, permissions, and user activity logs"
	groups["FP-FBA Role: Developer"] = "In-progress use: access pages that are experimental or under development"
	groups["FP-FBA Role: Recycler"] = "Impending removal: access pages that are under development for removal"
	return groups
}
