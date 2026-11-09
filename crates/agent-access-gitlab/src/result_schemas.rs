//! Result schemas for every GitLab action, bundled from JSON split by area.
use agent_access_provider::ResultSchemaBundle;

pub(crate) static RESULT_SCHEMAS: ResultSchemaBundle = ResultSchemaBundle::new(&[
    include_str!("result-schemas/issues-merge-requests.json"),
    include_str!("result-schemas/repository-ci-admin.json"),
]);
