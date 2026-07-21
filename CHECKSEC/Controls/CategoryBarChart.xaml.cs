using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using CHECKSEC.Core.Models;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
using WinRT;
using Windows.UI;

namespace CHECKSEC.Controls;

public sealed partial class CategoryBarChart : UserControl
{
	public static readonly DependencyProperty ItemsSourceProperty = DependencyProperty.Register("ItemsSource", typeof(object), typeof(CategoryBarChart), new PropertyMetadata(null, OnItemsSourceChanged));

	public object ItemsSource
	{
		get
		{
			return GetValue(ItemsSourceProperty);
		}
		set
		{
			SetValue(ItemsSourceProperty, value);
		}
	}

	public CategoryBarChart()
	{
		InitializeComponent();
		base.Unloaded += OnUnloaded;
	}

	private void OnUnloaded(object sender, RoutedEventArgs e)
	{
		if (ItemsSource is INotifyCollectionChanged notifyCollectionChanged)
		{
			notifyCollectionChanged.CollectionChanged -= OnCollectionChanged;
		}
	}

	private static void OnItemsSourceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is CategoryBarChart categoryBarChart)
		{
			if (e.OldValue is INotifyCollectionChanged notifyCollectionChanged)
			{
				notifyCollectionChanged.CollectionChanged -= categoryBarChart.OnCollectionChanged;
			}
			if (e.NewValue is INotifyCollectionChanged notifyCollectionChanged2)
			{
				notifyCollectionChanged2.CollectionChanged += categoryBarChart.OnCollectionChanged;
			}
			categoryBarChart.DrawBars();
		}
	}

	private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
	{
		DrawBars();
	}

	private void DrawBars()
	{
		BarsPanel.Children.Clear();
		if (!(ItemsSource is IEnumerable<SecurityScore> enumerable))
		{
			return;
		}
		foreach (SecurityScore score in enumerable)
		{
			Grid grid = new Grid
			{
				Height = 32.0
			};
			grid.ColumnDefinitions.Add(new ColumnDefinition
			{
				Width = new GridLength(140.0)
			});
			grid.ColumnDefinitions.Add(new ColumnDefinition
			{
				Width = new GridLength(1.0, GridUnitType.Star)
			});
			grid.ColumnDefinitions.Add(new ColumnDefinition
			{
				Width = new GridLength(50.0)
			});
			TextBlock categoryLabel = new TextBlock
			{
				Text = score.Category,
				FontSize = 12.0,
				VerticalAlignment = VerticalAlignment.Center,
				TextTrimming = TextTrimming.CharacterEllipsis,
				Margin = new Thickness(0.0, 0.0, 8.0, 0.0)
			};
			Grid.SetColumn(categoryLabel, 0);
			grid.Children.Add(categoryLabel);
			Border border = new Border
			{
				Background = new SolidColorBrush(Color.FromArgb(30, 128, 128, 128)),
				CornerRadius = new CornerRadius(4.0),
				Height = 16.0,
				VerticalAlignment = VerticalAlignment.Center
			};
			Grid.SetColumn(border, 1);
			grid.Children.Add(border);
			Color color = score.Grade switch
			{
				"A" => Color.FromArgb(byte.MaxValue, 76, 175, 80), 
				"B" => Color.FromArgb(byte.MaxValue, 139, 195, 74), 
				"C" => Color.FromArgb(byte.MaxValue, byte.MaxValue, 152, 0), 
				"D" => Color.FromArgb(byte.MaxValue, byte.MaxValue, 87, 34), 
				"F" => Color.FromArgb(byte.MaxValue, 244, 67, 54), 
				_ => Color.FromArgb(byte.MaxValue, 120, 144, 156), 
			};
			Border barFill = new Border
			{
				Background = new SolidColorBrush(color),
				CornerRadius = new CornerRadius(4.0),
				Height = 16.0,
				HorizontalAlignment = HorizontalAlignment.Left,
				VerticalAlignment = VerticalAlignment.Center,
				Width = 0.0
			};
			border.SizeChanged += delegate(object s, SizeChangedEventArgs e)
			{
				barFill.Width = Math.Max(0.0, e.NewSize.Width * score.ScorePercent / 100.0);
			};
			Grid.SetColumn(barFill, 1);
			grid.Children.Add(barFill);
			TextBlock percentLabel = new TextBlock
			{
				Text = $"{score.ScorePercent}%",
				FontSize = 12.0,
				FontWeight = FontWeights.SemiBold,
				VerticalAlignment = VerticalAlignment.Center,
				HorizontalAlignment = HorizontalAlignment.Right
			};
			Grid.SetColumn(percentLabel, 2);
			grid.Children.Add(percentLabel);
			BarsPanel.Children.Add(grid);
		}
	}
}
