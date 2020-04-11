use smallpt::*;
use std::path::Path;
use std::fs::File;
use std::io::BufWriter;
use std::time::Instant;

fn create_scene() -> Scene {
    let mut scene = Scene::init();

    // Spheres
    // Mirror
    scene.add(Box::new(Sphere::new(
        16.5,
        Vec3::new(27.0, 16.5, 47.0),
        Material::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(1.0, 1.0, 1.0), BSDF::Mirror),
    )));

    // Glass
    scene.add(Box::new(Sphere::new(
        16.5,
        Vec3::new(73.0, 16.5, 78.0),
        Material::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(1.0, 1.0, 1.0), BSDF::Glass),
    )));

    // Planes
    // Bottom
    scene.add(Box::new(Plane::new(
        Vec3::new(0.0, 0.0, 0.0),
        Vec3::new(0.0, 1.0, 0.0),
        Material::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(0.75, 0.75, 0.75), BSDF::Diffuse),
    )));

    // Left
    scene.add(Box::new(Plane::new(
        Vec3::new(1.0, 0.0, 0.0),
        Vec3::new(1.0, 0.0, 0.0),
        Material::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(0.75, 0.25, 0.25), BSDF::Diffuse),
    )));

    // Right
    scene.add(Box::new(Plane::new(
        Vec3::new(99.0, 0.0, 0.0),
        Vec3::new(-1.0, 0.0, 0.0),
        Material::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(0.25, 0.25, 0.75), BSDF::Diffuse),
    )));

    // Front
    scene.add(Box::new(Plane::new(
        Vec3::new(0.0, 0.0, 0.0),
        Vec3::new(0.0, 0.0, 1.0),
        Material::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(0.75, 0.75, 0.75), BSDF::Diffuse),
    )));

    // Back
    scene.add(Box::new(Plane::new(
        Vec3::new(0.0, 0.0, 170.0),
        Vec3::new(0.0, 0.0, -1.0),
        Material::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(0.0, 0.0, 0.0), BSDF::Diffuse),
    )));

    // Top
    scene.add(Box::new(Plane::new(
        Vec3::new(0.0, 81.6, 0.0),
        Vec3::new(0.0, -1.0, 0.0),
        Material::new(Vec3::new(0.0, 0.0, 0.0), Vec3::new(0.75, 0.75, 0.75), BSDF::Diffuse),
    )));

    // Light (emissive rectangle)
    scene.add(Box::new(Rectangle::new(
        Vec3::new(50.0, 81.5, 50.0),
        Vec3::new(0.0, -1.0, 0.0),
        Vec3::new(1.0, 0.0, 0.0),
        Vec3::new(0.0, 0.0, 1.0),
        33.0,
        33.0,
        Material::new(Vec3::new(12.0, 12.0, 12.0), Vec3::new(0.0, 0.0, 0.0), BSDF::Diffuse),
    )));

    scene
}

fn render_scene(scene: &Scene, width: usize, height: usize, backbuffer: &mut [Vec3]) {
    let num_samples = 512;
    let mut num_rays = 0;
    let camera = Camera {
        origin: Vec3::new(50.0, 50.0, 200.0),
        forward: Vec3::new(0.0, -0.05, -1.0).normalize(),
        right: Vec3::new(1.0, 0.0, 0.0).normalize(),
        up: Vec3::new(0.0, 1.0, 0.0).normalize(),
    };

    println!("starting trace on {} cores", num_cpus::get());
    trace(&scene, &camera, width, height, num_samples, backbuffer, &mut num_rays);
    println!("finished tracing!");
}

fn save_png_file(width: usize, height: usize, backbuffer: &[Vec3]) {
    let mut data = vec![0u8; width * height * 3];
    for i in 0..width * height {
        let color = saturate(tonemap(backbuffer[i]));

        data[i*3+0] = (color.x * 255.0).round() as u8; // r
        data[i*3+1] = (color.y * 255.0).round() as u8; // g
        data[i*3+2] = (color.z * 255.0).round() as u8; // b
    }

    let path = Path::new("render.png");
    let file = File::create(path).unwrap();
    let ref mut w = BufWriter::new(file);

    let mut encoder = png::Encoder::new(w, width as u32, height as u32);
    encoder.set_color(png::ColorType::RGB);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().unwrap();

    writer.write_image_data(&data).unwrap(); // Save
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let width = 256;
    let height = 256;
    let scene = create_scene();
    let mut backbuffer = vec![Vec3::new(0.0, 0.0, 0.0); width * height];
    println!("starting render!");
    let now = Instant::now();

    match args.get(1) {
        Some(dest) => {
            println!("teleforking to {} for render!", dest);
            telefork::yoyo(dest, || {
                render_scene(&scene, width, height, &mut backbuffer);
            })
        }
        None => {
            println!("doing render locally");
            render_scene(&scene, width, height, &mut backbuffer);
        }
    }

    println!("done tracing in {:?}, saving to render.png", now.elapsed());
    save_png_file(width, height, &backbuffer);
}
