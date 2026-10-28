use rudra_runtime::{EntityId, Registry};

#[derive(Debug, Eq, PartialEq)]
struct Project(&'static str);

#[derive(Debug, Eq, PartialEq)]
struct Scene(&'static str);

#[derive(Debug, Eq, PartialEq)]
struct Asset(&'static str);

#[test]
fn one_runtime_supports_unrelated_non_office_entity_types() {
    let mut projects = Registry::new();
    let mut scenes = Registry::new();
    let mut assets = Registry::new();

    let project_a: EntityId<Project> = projects.insert(Project("alpha")).unwrap();
    let project_b = projects.insert(Project("beta")).unwrap();
    let scene = scenes.insert(Scene("intro")).unwrap();
    let asset = assets.insert(Asset("logo")).unwrap();

    assert_ne!(project_a, project_b);
    assert_eq!(scenes.get(scene), Some(&Scene("intro")));
    assert_eq!(assets.get(asset), Some(&Asset("logo")));

    assert_eq!(projects.remove(project_a), Some(Project("alpha")));
    assert_eq!(projects.get(project_a), None);
    assert_eq!(projects.get(project_b), Some(&Project("beta")));
}
