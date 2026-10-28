//! Measured capture pixels and physical desktop pixels are distinct spaces.
use crate::{AutomationError, AutomationResult, ErrorCode, Rect, ScreenPoint};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaptureGeometry {
    pub window_id: String,
    pub hwnd: String,
    pub pid: u32,
    pub process_birth: u64,
    pub monitor_identity: String,
    pub geometry_generation: u64,
    pub inspection_coordinate_space: String,
    pub capture_coordinate_space: String,
    pub screen_coordinate_space: String,
    pub window_rect_screen_physical: Rect,
    pub client_rect_screen_physical: Rect,
    pub content_rect_capture_pixels: Rect,
    pub capture_width_pixels: u32,
    pub capture_height_pixels: u32,
    /// GetDpiForWindow describes the TARGET's awareness; 96 is valid for an unaware HWND.
    pub target_window_dpi: u32,
    /// Measured separately by GetScaleFactorForMonitor, never mislabeled as window DPI.
    pub monitor_scale_percent: i32,
    pub dpi_awareness_context: String,
    pub transform_provenance: String,
    /// Metadata is not a calibration proof. PrintWindow has app-defined rendering.
    pub mapping_verified: bool,
}

impl CaptureGeometry {
    pub fn capture_to_screen(&self, x: u32, y: u32, generation: u64) -> AutomationResult<ScreenPoint> {
        if !self.mapping_verified || generation != self.geometry_generation || self.capture_width_pixels == 0
            || self.capture_height_pixels == 0 || !self.window_rect_screen_physical.is_actionable()
            || x >= self.capture_width_pixels || y >= self.capture_height_pixels {
            return Err(AutomationError::new(ErrorCode::CoordinateMappingUnverified,
                "stale geometry generation or pixel outside measured capture"));
        }
        // Project pixel CENTRES into a half-open destination rectangle. Unlike
        // rounded edges, this cannot land at right/bottom when downscaling.
        let map = |origin: i32, size: i32, pixel: u32, count: u32| -> AutomationResult<i32> {
            let offset = ((2 * i128::from(pixel) + 1) * i128::from(size)) / (2 * i128::from(count));
            i32::try_from(i128::from(origin) + offset).map_err(|_| AutomationError::new(
                ErrorCode::CoordinateMappingUnverified, "capture mapping overflow"))
        };
        Ok(ScreenPoint {
            x: map(self.window_rect_screen_physical.x, self.window_rect_screen_physical.width, x, self.capture_width_pixels)?,
            y: map(self.window_rect_screen_physical.y, self.window_rect_screen_physical.height, y, self.capture_height_pixels)?,
        })
    }

    pub fn screen_to_capture(&self, point: ScreenPoint, generation: u64) -> AutomationResult<(u32, u32)> {
        self.capture_to_screen(0, 0, generation)?;
        let r = self.window_rect_screen_physical;
        let x = i64::from(point.x) - i64::from(r.x);
        let y = i64::from(point.y) - i64::from(r.y);
        if x < 0 || y < 0 || x >= i64::from(r.width) || y >= i64::from(r.height) {
            return Err(AutomationError::new(ErrorCode::CoordinateMappingUnverified, "screen point outside measured window"));
        }
        Ok(((((2*i128::from(x)+1) * i128::from(self.capture_width_pixels)) / (2*i128::from(r.width))) as u32,
            (((2*i128::from(y)+1) * i128::from(self.capture_height_pixels)) / (2*i128::from(r.height))) as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(width: i32, height: i32) -> CaptureGeometry {
        CaptureGeometry { window_id:"owned".into(), hwnd:"0x1".into(), pid:1, process_birth:2,
            monitor_identity:"monitor-1".into(), geometry_generation:3, inspection_coordinate_space:"SCREEN_PHYSICAL_PIXEL".into(),
            capture_coordinate_space:"CAPTURE_PIXEL".into(), screen_coordinate_space:"SCREEN_PHYSICAL_PIXEL".into(),
            window_rect_screen_physical:Rect{x:-100,y:39,width,height}, client_rect_screen_physical:Rect::default(),
            content_rect_capture_pixels:Rect{x:0,y:0,width:760,height:560}, capture_width_pixels:760,capture_height_pixels:560,
            target_window_dpi:96,monitor_scale_percent:125,dpi_awareness_context:"per_monitor_v2".into(),transform_provenance:"test-only".into(),mapping_verified:true }
    }
    #[test] fn rational_125_mapping_and_negative_origin() {
        let g=sample(950,700);
        assert_eq!(g.capture_to_screen(380,280,3).unwrap(),ScreenPoint{x:375,y:389});
        assert_eq!(g.screen_to_capture(ScreenPoint{x:375,y:389},3).unwrap(),(380,280));
        assert_eq!(g.capture_to_screen(1,1,3).unwrap(),ScreenPoint{x:-99,y:40});
    }
    #[test] fn mapping_scales_and_stale_generation_refuse() {
        for (w,h) in [(760,560),(950,700),(1140,840),(1520,1120)] {
            let g=sample(w,h);
            assert_eq!(g.capture_to_screen(0,0,3).unwrap(),ScreenPoint{x:-100+w/(2*760),y:39+h/(2*560)});
            assert!(g.capture_to_screen(1,1,2).is_err());
            assert!(g.capture_to_screen(760,0,3).is_err());
        }
        assert!(sample(0,700).capture_to_screen(0,0,3).is_err());
    }
    #[test] fn downscale_and_fractional_edges_stay_inside_and_unverified_mapping_refuses() {
        for (w,h) in [(380,280),(608,448),(950,700),(1140,840)] {
            let g=sample(w,h);
            let p=g.capture_to_screen(759,559,3).unwrap();
            assert!(p.x>=-100 && p.x < -100+w && p.y>=39 && p.y <39+h);
        }
        let g=sample(950,700);
        for x in 0..760 {
            let p=g.capture_to_screen(x,0,3).unwrap();
            assert_eq!(g.screen_to_capture(p,3).unwrap().0,x);
        }
        let mut unknown=g; unknown.mapping_verified=false;
        assert_eq!(unknown.capture_to_screen(0,0,3).unwrap_err().code,ErrorCode::CoordinateMappingUnverified);
        // A public deserialized geometry must never panic on widened arithmetic.
        let mut huge=sample(i32::MAX,i32::MAX);
        huge.capture_width_pixels=u32::MAX; huge.capture_height_pixels=u32::MAX;
        assert!(huge.capture_to_screen(u32::MAX-1,0,3).is_ok());
        huge.window_rect_screen_physical.x=i32::MAX;
        assert_eq!(huge.capture_to_screen(u32::MAX-1,0,3).unwrap_err().code,ErrorCode::CoordinateMappingUnverified);
    }
}
