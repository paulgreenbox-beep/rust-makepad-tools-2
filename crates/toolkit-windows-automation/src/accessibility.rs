//! Application-neutral accessibility snapshots consumed by the Windows UIA bridge.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

pub(crate) const MAKEPAD_EMPTY_VALUE_SENTINEL: &str = "__MAKEPAD_UIA_CLEAR_9E3779B97F4A7C15__";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessibilityRole {
    Button,
    CheckBox,
    ComboBox,
    Custom,
    DataGrid,
    DataItem,
    Document,
    Edit,
    Group,
    Hyperlink,
    Image,
    List,
    ListItem,
    Menu,
    MenuBar,
    MenuItem,
    Pane,
    ProgressBar,
    RadioButton,
    ScrollBar,
    Slider,
    Spinner,
    SplitButton,
    StatusBar,
    Tab,
    TabItem,
    Text,
    TitleBar,
    ToolBar,
    Tree,
    TreeItem,
    Window,
    #[default]
    Unknown,
}

impl AccessibilityRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Button => "button",
            Self::CheckBox => "checkbox",
            Self::ComboBox => "combobox",
            Self::Custom => "custom",
            Self::DataGrid => "datagrid",
            Self::DataItem => "dataitem",
            Self::Document => "document",
            Self::Edit => "edit",
            Self::Group => "group",
            Self::Hyperlink => "hyperlink",
            Self::Image => "image",
            Self::List => "list",
            Self::ListItem => "listitem",
            Self::Menu => "menu",
            Self::MenuBar => "menubar",
            Self::MenuItem => "menuitem",
            Self::Pane => "pane",
            Self::ProgressBar => "progressbar",
            Self::RadioButton => "radiobutton",
            Self::ScrollBar => "scrollbar",
            Self::Slider => "slider",
            Self::Spinner => "spinner",
            Self::SplitButton => "splitbutton",
            Self::StatusBar => "statusbar",
            Self::Tab => "tab",
            Self::TabItem => "tabitem",
            Self::Text => "text",
            Self::TitleBar => "titlebar",
            Self::ToolBar => "toolbar",
            Self::Tree => "tree",
            Self::TreeItem => "treeitem",
            Self::Window => "window",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AccessibilityRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl AccessibilityRect {
    pub fn is_valid(self) -> bool {
        self.x.is_finite()
            && self.y.is_finite()
            && self.width.is_finite()
            && self.height.is_finite()
            && self.width >= 0.0
            && self.height >= 0.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccessibilityActions {
    pub invoke: bool,
    pub select: bool,
    pub add_to_selection: bool,
    pub remove_from_selection: bool,
    pub focus: bool,
    pub set_value: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccessibilitySelection {
    pub can_select_multiple: bool,
    pub is_selection_required: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessibilityNode {
    /// Stable for the lifetime of the logical widget, not a child index or HWND.
    pub id: String,
    pub role: AccessibilityRole,
    pub name: String,
    pub bounds: AccessibilityRect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Non-serialized lifecycle token. When set, a UIA provider bound to an
    /// older token must not act on a newer logical instance with the same ID.
    #[serde(skip)]
    pub instance_key: Option<u64>,
    pub visible: bool,
    pub enabled: bool,
    pub focused: bool,
    pub selected: Option<bool>,
    pub actions: AccessibilityActions,
    pub selection: Option<AccessibilitySelection>,
    pub children: Vec<AccessibilityNode>,
}

impl AccessibilityNode {
    pub fn new(
        id: impl Into<String>,
        role: AccessibilityRole,
        name: impl Into<String>,
        bounds: AccessibilityRect,
    ) -> Self {
        Self {
            id: id.into(),
            role,
            name: name.into(),
            bounds,
            value: None,
            instance_key: None,
            visible: true,
            enabled: true,
            focused: false,
            selected: None,
            actions: AccessibilityActions::default(),
            selection: None,
            children: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessibilityTree {
    pub generation: u64,
    pub root: AccessibilityNode,
}

impl AccessibilityTree {
    pub fn new(root: AccessibilityNode) -> Result<Self, AccessibilityTreeError> {
        let tree = Self {
            generation: 0,
            root,
        };
        tree.validate()?;
        Ok(tree)
    }

    pub fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    pub fn validate(&self) -> Result<(), AccessibilityTreeError> {
        let mut ids = HashMap::<String, String>::new();
        validate_node(&self.root, None, &mut ids)
    }

    pub(crate) fn index(&self) -> Result<AccessibilityIndex, AccessibilityTreeError> {
        self.validate()?;
        let mut nodes = HashMap::new();
        flatten_node(&self.root, None, &mut nodes);
        Ok(AccessibilityIndex {
            generation: self.generation,
            root_id: self.root.id.clone(),
            nodes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessibilityTreeError {
    EmptyId { path: String },
    DuplicateId { id: String },
    InvalidBounds { id: String },
}

impl fmt::Display for AccessibilityTreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId { path } => write!(formatter, "accessibility node id is empty at {path}"),
            Self::DuplicateId { id } => write!(formatter, "duplicate accessibility node id: {id}"),
            Self::InvalidBounds { id } => {
                write!(formatter, "invalid bounds for accessibility node: {id}")
            }
        }
    }
}

impl std::error::Error for AccessibilityTreeError {}

#[derive(Clone, Debug)]
pub(crate) struct AccessibilityIndex {
    pub generation: u64,
    pub root_id: String,
    pub nodes: HashMap<String, IndexedAccessibilityNode>,
}

#[derive(Clone, Debug)]
pub(crate) struct IndexedAccessibilityNode {
    pub node: AccessibilityNode,
    pub parent_id: Option<String>,
    pub children: Vec<String>,
}

fn validate_node(
    node: &AccessibilityNode,
    parent: Option<&str>,
    ids: &mut HashMap<String, String>,
) -> Result<(), AccessibilityTreeError> {
    if node.id.trim().is_empty() {
        return Err(AccessibilityTreeError::EmptyId {
            path: parent.unwrap_or("root").to_owned(),
        });
    }
    if ids.insert(node.id.clone(), node.id.clone()).is_some() {
        return Err(AccessibilityTreeError::DuplicateId {
            id: node.id.clone(),
        });
    }
    if !node.bounds.is_valid() {
        return Err(AccessibilityTreeError::InvalidBounds {
            id: node.id.clone(),
        });
    }
    for child in &node.children {
        validate_node(child, Some(&node.id), ids)?;
    }
    Ok(())
}

fn flatten_node(
    node: &AccessibilityNode,
    parent_id: Option<&str>,
    nodes: &mut HashMap<String, IndexedAccessibilityNode>,
) {
    let children = node.children.iter().map(|child| child.id.clone()).collect();
    nodes.insert(
        node.id.clone(),
        IndexedAccessibilityNode {
            node: node.clone(),
            parent_id: parent_id.map(str::to_owned),
            children,
        },
    );
    for child in &node.children {
        flatten_node(child, Some(&node.id), nodes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect() -> AccessibilityRect {
        AccessibilityRect {
            x: 10.0,
            y: 20.0,
            width: 100.0,
            height: 30.0,
        }
    }

    #[test]
    fn index_preserves_parent_children_and_selection_state() {
        let mut root = AccessibilityNode::new("root", AccessibilityRole::Window, "App", rect());
        root.selection = Some(AccessibilitySelection {
            can_select_multiple: false,
            is_selection_required: true,
        });
        let mut item = AccessibilityNode::new("item", AccessibilityRole::TabItem, "First", rect());
        item.selected = Some(true);
        item.actions.select = true;
        root.children.push(item);

        let tree = AccessibilityTree::new(root).unwrap().with_generation(7);
        let index = tree.index().unwrap();
        assert_eq!(index.generation, 7);
        assert_eq!(index.root_id, "root");
        assert_eq!(index.nodes["item"].parent_id.as_deref(), Some("root"));
        assert_eq!(index.nodes["root"].children, vec!["item"]);
        assert_eq!(index.nodes["item"].node.selected, Some(true));
    }

    #[test]
    fn duplicate_ids_and_invalid_bounds_are_rejected() {
        let mut root = AccessibilityNode::new("same", AccessibilityRole::Window, "App", rect());
        root.children.push(AccessibilityNode::new(
            "same",
            AccessibilityRole::Button,
            "Save",
            rect(),
        ));
        assert!(matches!(
            AccessibilityTree::new(root),
            Err(AccessibilityTreeError::DuplicateId { .. })
        ));

        let invalid = AccessibilityNode::new(
            "invalid",
            AccessibilityRole::Text,
            "Text",
            AccessibilityRect {
                width: -1.0,
                ..rect()
            },
        );
        assert!(matches!(
            AccessibilityTree::new(invalid),
            Err(AccessibilityTreeError::InvalidBounds { .. })
        ));
    }
}
